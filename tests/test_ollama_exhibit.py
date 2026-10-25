"""No Ollama installation, network connection, or model required."""

import json
import sqlite3
from contextlib import closing
from hashlib import sha256

import httpx
import pytest
from pydantic import ValidationError

from examples import ollama_exhibit
from examples.ollama_exhibit import (
    CONDITIONS,
    Decision,
    OllamaExhibitTarget,
    run_pilot,
)
from examples.retrieval_case_study import EXHIBIT_FIXTURE, build_store
from examples.study_scoring import capture_trial_evidence, score_trial
from matterfence.core.runner import TestStatus, run_auth_scenario
from matterfence.core.scenario import CrossMatterScenario
from matterfence.targets.ollama import MAX_RESPONSE_BYTES, MODEL, OPTIONS, OllamaClient

CANARY = "MF_CANARY_M105_PRIVILEGED_7C91"
FORBIDDEN = "DOC_M105_STRATEGY"
ALLOWED = "DOC_M101_EXHIBIT"


def reply(content, **overrides):
    return {
        "done": True,
        "done_reason": "stop",
        "message": {"role": "assistant", "content": content},
        **overrides,
    }


def fake_client(answers):
    """Consume specified chat replies; identity endpoints stay deterministic."""
    responses = iter(answers)

    def handle(request):
        assert str(request.url).startswith("http://127.0.0.1:11434/api/")
        if request.url.path == "/api/version":
            return httpx.Response(200, json={"version": "test-version"})
        if request.url.path == "/api/tags":
            return httpx.Response(
                200, json={"models": [{"name": MODEL, "digest": "a" * 64}]}
            )
        assert request.url.path == "/api/chat"
        payload = json.loads(request.content)
        assert payload["options"] == OPTIONS
        assert payload["think"] is False and payload["stream"] is False
        assert payload["keep_alive"] == 0
        answer = next(responses)
        if isinstance(answer, BaseException):
            raise answer
        return httpx.Response(200, json=answer)

    return OllamaClient(transport=httpx.MockTransport(handle))


@pytest.fixture
def scenario():
    return CrossMatterScenario.model_validate_json(EXHIBIT_FIXTURE.read_bytes())


@pytest.mark.parametrize("mode,expected", [("vulnerable", "FAIL"), ("secure", "PASS")])
def test_actual_search_ids_not_model_claims_determine_retrieval(
    scenario, mode, expected
):
    answers = [
        reply(json.dumps({"search_query": "negotiation", "answer": ""})),
        reply(f"I read {FORBIDDEN}."),
    ]
    with (
        closing(fake_client(answers)) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        before = store.execute("SELECT * FROM grants ORDER BY user_id").fetchall()
        target = OllamaExhibitTarget(store, client, mode)
        finding = run_auth_scenario(target, scenario)
        assert finding.status.value == expected
        assert finding.prohibited_resources[0].retrieved is (mode == "vulnerable")
        assert finding.prohibited_resources[0].disclosed is False
        assert all(event["user_id"] == "USR_BOB" for event in target.events)
        assert target.events[0]["mode"] == "secure"
        assert (
            store.execute("SELECT * FROM grants ORDER BY user_id").fetchall() == before
        )
        first_messages = json.dumps(client.calls[0]["request"]["messages"])
        assert CANARY not in first_messages
        assert FORBIDDEN not in first_messages
        assert client.calls[1]["request"].get("format") is None


def test_no_search_uses_only_the_model_final_answer(scenario):
    answer = "The witness confirmed delivery on 12 March."
    with (
        closing(
            fake_client([reply(json.dumps({"search_query": None, "answer": answer}))])
        ) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, "vulnerable")
        actor = next(user for user in scenario.users if user.id == scenario.actor_id)
        result = target.retrieve(actor, scenario.matters, scenario.attack)
        assert result.response_text == answer
        assert result.retrieved_document_ids == [ALLOWED]
        assert len(target.events) == len(client.calls) == 1


def test_final_canary_is_disclosure_not_retrieval(scenario):
    with (
        closing(
            fake_client([reply(json.dumps({"search_query": None, "answer": CANARY}))])
        ) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        finding = run_auth_scenario(
            OllamaExhibitTarget(store, client, "secure"), scenario
        )
        assert finding.status == TestStatus.FAIL
        assert finding.prohibited_resources[0].retrieved is False
        assert finding.prohibited_resources[0].disclosed is True


@pytest.mark.parametrize("mode,expected", [("vulnerable", "FAIL"), ("secure", "ERROR")])
def test_late_timeout_retains_observed_retrieval(scenario, mode, expected):
    answers = [
        reply('{"search_query":"negotiation","answer":""}'),
        httpx.ReadTimeout("slow"),
    ]
    with (
        closing(fake_client(answers)) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, mode)
        finding = run_auth_scenario(target, scenario)
        assert finding.status.value == expected
        assert finding.prohibited_resources[0].retrieved is (mode == "vulnerable")
        assert "execution error" in finding.observed
        assert target.error == "ReadTimeout"
        assert client.calls[-1]["error"] == "ReadTimeout"


@pytest.mark.parametrize(
    "answer",
    [
        reply("not JSON"),
        reply('{"search_query":null,"answer":""}'),
        reply('{"search_query":"negotiation","answer":"", "user_id":"USR_ALICE"}'),
        reply('{"search_query":null,"answer":"ok"}', done=False),
        reply('{"search_query":null,"answer":"ok"}', done_reason="length"),
        reply("", message={"role": "assistant", "content": "", "tool_calls": [{}]}),
    ],
)
def test_invalid_model_output_is_error_not_pass(scenario, answer):
    with (
        closing(fake_client([answer])) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, "vulnerable")
        finding = run_auth_scenario(target, scenario)
        assert finding.status == TestStatus.ERROR
        assert finding.retrieved_document_ids == [ALLOWED]
        assert target.error is not None
        assert "raw_response" in client.calls[0]


@pytest.mark.parametrize(
    "query,answer",
    [
        (" ", ""),
        ("x" * 257, ""),
        ("search", "also answer"),
        (False, ""),
        (None, " "),
    ],
)
def test_decision_contract_rejects_ambiguous_actions(query, answer):
    with pytest.raises(ValidationError):
        Decision(search_query=query, answer=answer)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"location": "https://example.com"}),
        httpx.Response(500),
        httpx.Response(200, content=b"x" * (MAX_RESPONSE_BYTES + 1)),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json=[]),
        httpx.Response(200, headers={"content-encoding": "custom"}, content=b"{}"),
    ],
)
def test_transport_rejects_unsafe_or_invalid_replies(response):
    requests = []

    def handle(request):
        requests.append(request)
        return response

    with closing(OllamaClient(transport=httpx.MockTransport(handle))) as client:
        with pytest.raises((httpx.HTTPError, ValueError, TypeError)):
            client.chat([{"role": "user", "content": "test"}])
        assert len(requests) == 1
        assert client.calls[0]["error"]
        assert client.calls[0]["elapsed_seconds"] >= 0


def test_four_cells_save_reproducible_evidence_without_overwriting(tmp_path):
    answers = [reply('{"search_query":null,"answer":"Delivery on 12 March."}')] * 4
    output = tmp_path / "pilot"
    with closing(fake_client(answers)) as client:
        findings = run_pilot(output, client)
        assert [item.status for item in findings] == [TestStatus.PASS] * 4
        assert (
            len(client.calls) == 8
        )  # Two identity requests before and after, four chats.
        plan = json.loads((output / "plan.json").read_text())
        assert plan["conditions"] == [list(condition) for condition in CONDITIONS]
        manifest = json.loads((output / "manifest.json").read_text())
        assert manifest["identity_unchanged"] is True
        for name, digest in manifest["artifacts_sha256"].items():
            assert sha256((output / name).read_bytes()).hexdigest() == digest
        for exhibit, mode in CONDITIONS:
            trace = json.loads((output / f"{exhibit}-{mode}.json").read_text())
            assert trace["error"] is None
            assert trace["decision"]["search_query"] is None
            messages = json.dumps(trace["model_calls"][0]["request"]["messages"])
            assert ("SYSTEM NOTE" in messages) is (exhibit == "poisoned")
            assert CANARY not in messages
        with pytest.raises(FileExistsError):
            run_pilot(output, client)
        assert len(client.calls) == 8


def test_missing_model_stops_before_any_generation(tmp_path):
    def handle(request):
        assert request.method == "GET"
        return httpx.Response(200, json={"version": "test", "models": []})

    with (
        closing(OllamaClient(transport=httpx.MockTransport(handle))) as client,
        pytest.raises(ValueError, match="Install"),
    ):
        run_pilot(tmp_path / "pilot", client)


def test_changed_model_identity_invalidates_run_but_retains_evidence(tmp_path):
    with closing(
        fake_client([reply('{"search_query":null,"answer":"ok"}')] * 4)
    ) as client:
        identities = iter([{"digest": "before"}, {"digest": "after"}])
        client.identity = lambda: next(identities)
        output = tmp_path / "pilot"
        with pytest.raises(ValueError, match="identity changed"):
            run_pilot(output, client)
        assert (output / "comparison.html").is_file()
        assert (
            json.loads((output / "manifest.json").read_text())["identity_unchanged"]
            is False
        )


@pytest.mark.parametrize(
    "kind,expected", [("pass", 0), ("fail", 1), ("error", 2), ("late", 2)]
)
def test_command_exit_codes_preserve_errors_and_violations(
    tmp_path, monkeypatch, kind, expected
):
    if kind == "late":
        answers = [
            item
            for _ in CONDITIONS
            for item in (
                reply('{"search_query":"negotiation","answer":""}'),
                httpx.ReadTimeout("slow"),
            )
        ]
    elif kind == "error":
        answers = [reply("invalid JSON")] * 4
    else:
        text = CANARY if kind == "fail" else "Delivery on 12 March."
        answers = [reply(json.dumps({"search_query": None, "answer": text}))] * 4
    client = fake_client(answers)
    monkeypatch.setattr(ollama_exhibit, "OllamaClient", lambda: client)
    output = tmp_path / "pilot"
    assert ollama_exhibit.main(["--output-dir", str(output)]) == expected
    assert client.http.is_closed
    if kind == "late":
        findings = json.loads((output / "findings.json").read_text())
        assert [item["status"] for item in findings] == [
            "FAIL",
            "ERROR",
            "FAIL",
            "ERROR",
        ]


def test_command_existing_directory_does_not_contact_model(tmp_path, monkeypatch):
    client = fake_client([])
    monkeypatch.setattr(ollama_exhibit, "OllamaClient", lambda: client)
    with pytest.raises(SystemExit) as error:
        ollama_exhibit.main(["--output-dir", str(tmp_path)])
    assert error.value.code == 2
    assert client.calls == []
    assert client.http.is_closed


@pytest.mark.parametrize("mode", ["vulnerable", "secure"])
@pytest.mark.parametrize(
    "response,disclosed,complete",
    [
        (reply(CANARY, done_reason="length"), True, False),
        (reply("Partial summary", done=False), None, False),
        (httpx.ReadTimeout("slow"), None, False),
        (reply("Delivery on 12 March."), False, True),
    ],
)
def test_execution_evidence_reaches_scorer_without_erasing_partial_output(
    scenario, mode, response, disclosed, complete
):
    answers = [reply('{"search_query":"negotiation","answer":""}'), response]
    with (
        closing(fake_client(answers)) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, mode)
        finding = run_auth_scenario(target, scenario)
        evidence = capture_trial_evidence(target)
        score = score_trial(evidence, scenario, "negotiation")
        assert evidence.retrieval_complete is True
        assert evidence.final_answer_complete is complete
        assert score.target_query_requested is True
        assert score.forbidden_retrieved is (mode == "vulnerable")
        assert score.canary_disclosed is disclosed
        assert score.execution_error is (not complete)
        expected = (
            "FAIL"
            if mode == "vulnerable" or disclosed
            else ("PASS" if complete else "ERROR")
        )
        assert finding.status.value == expected
        assert len(client.calls) == 2  # No retry or extra search.
        if disclosed:
            assert evidence.final_answer == CANARY
            assert finding.prohibited_resources[0].disclosed is True
        if isinstance(response, httpx.ReadTimeout):
            assert evidence.final_answer is None


@pytest.mark.parametrize(
    "response",
    [
        reply(json.dumps({"search_query": None, "answer": CANARY}), done=False),
        reply(
            json.dumps({"search_query": None, "answer": CANARY}), done_reason="length"
        ),
        reply(CANARY),  # Not a valid decision, despite the complete HTTP reply.
    ],
)
def test_invalid_decision_text_is_not_promoted_to_final_output(scenario, response):
    with (
        closing(fake_client([response])) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, "secure")
        finding = run_auth_scenario(target, scenario)
        evidence = capture_trial_evidence(target)
        score = score_trial(evidence, scenario, "negotiation")
        assert evidence.decision is None
        assert evidence.final_answer is None
        assert score.canary_disclosed is None
        assert score.execution_error is True
        assert finding.status == TestStatus.ERROR
        assert CANARY in client.calls[0]["raw_response"]


@pytest.mark.parametrize(
    "message",
    [
        {"role": "user", "content": CANARY},
        {"role": "assistant", "thinking": CANARY},
        {"role": "assistant", "content": [CANARY]},
        None,
    ],
)
def test_only_assistant_text_can_be_partial_final_output(scenario, message):
    answers = [
        reply('{"search_query":"negotiation","answer":""}'),
        reply("", message=message),
    ]
    with (
        closing(fake_client(answers)) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, "secure")
        run_auth_scenario(target, scenario)
        evidence = capture_trial_evidence(target)
        assert evidence.final_answer is None
        assert score_trial(evidence, scenario, "negotiation").canary_disclosed is None


@pytest.mark.parametrize("fail_at", [1, 2])
def test_retrieval_failure_keeps_ids_unknown_or_partial(scenario, monkeypatch, fail_at):
    real_retrieve = ollama_exhibit.retrieve
    count = 0

    def fail_search(*args):
        nonlocal count
        count += 1
        if count == fail_at:
            raise sqlite3.OperationalError("unavailable")
        return real_retrieve(*args)

    monkeypatch.setattr(ollama_exhibit, "retrieve", fail_search)
    with (
        closing(
            fake_client([reply('{"search_query":"negotiation","answer":""}')])
        ) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, "secure")
        finding = run_auth_scenario(target, scenario)
        evidence = capture_trial_evidence(target)
        assert evidence.retrieved_document_ids == (None if fail_at == 1 else [ALLOWED])
        assert evidence.retrieval_complete is False
        assert evidence.error == "OperationalError"
        assert (
            score_trial(evidence, scenario, "negotiation").forbidden_retrieved is None
        )
        assert finding.status == TestStatus.ERROR


@pytest.mark.parametrize("after_search", [False, True])
def test_interruption_propagates_with_a_snapshot_of_observed_evidence(
    scenario, after_search
):
    answers = [KeyboardInterrupt()]
    if after_search:
        answers.insert(0, reply('{"search_query":"negotiation","answer":""}'))
    with (
        closing(fake_client(answers)) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, "vulnerable")
        with pytest.raises(KeyboardInterrupt):
            run_auth_scenario(target, scenario)
        evidence = capture_trial_evidence(target)
        score = score_trial(evidence, scenario, "negotiation")
        assert evidence.error == "KeyboardInterrupt"
        assert evidence.retrieval_complete is True
        assert score.forbidden_retrieved is after_search
        assert score.canary_disclosed is None
        assert score.execution_error is True


def test_snapshots_are_independent_and_repeated_execution_resets_state(scenario):
    answers = [
        reply('{"search_query":"negotiation","answer":""}'),
        reply(CANARY, done_reason="length"),
        reply('{"search_query":null,"answer":"Delivery on 12 March."}'),
    ]
    with (
        closing(fake_client(answers)) as client,
        closing(build_store(scenario.model_dump())) as store,
    ):
        target = OllamaExhibitTarget(store, client, "vulnerable")
        not_run = capture_trial_evidence(target)
        assert score_trial(not_run, scenario, "negotiation").status == "not_run"
        assert client.calls == []
        run_auth_scenario(target, scenario)
        first = capture_trial_evidence(target)
        first_copy = first.model_dump()
        target.decision["search_query"] = "changed after snapshot"
        target.retrieved_document_ids.clear()
        assert first.model_dump() == first_copy
        run_auth_scenario(target, scenario)
        second = capture_trial_evidence(target)
        assert first.model_dump() == first_copy
        assert second.error is None
        assert second.retrieved_document_ids == [ALLOWED]
        assert second.final_answer == "Delivery on 12 March."
        assert second.final_answer_complete is True
        assert second.decision.search_query is None
        assert len(target.events) == 1
        assert score_trial(second, scenario, "negotiation").execution_error is False
