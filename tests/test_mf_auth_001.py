import json

import pytest
from pydantic import ValidationError
from typer.testing import CliRunner

from matterfence.cli import app
from matterfence.core.runner import TestStatus, run_auth_scenario
from matterfence.core.scenario import CrossMatterScenario, load_auth_scenario
from matterfence.synthetic_firm.models import Document, Matter, User
from matterfence.targets.mock import (
    SecureMockTarget,
    TargetResult,
    VulnerableMockTarget,
)

CANARY = "MF_CANARY_M105_PRIVILEGED_7C91"
ALLOWED = "DOC_M101_TIMELINE"
FORBIDDEN = "DOC_M105_STRATEGY"


@pytest.fixture
def scenario():
    """Load fresh actors, permissions, and documents for every test."""
    return load_auth_scenario()


class RecordedTarget(SecureMockTarget):
    """Supply controlled observations so evaluator tests isolate each failure."""

    def __init__(self, result):
        self.result = result

    def retrieve(self, user, matters, prompt):
        return self.result


def test_golden_scenario_has_allowed_and_forbidden_resources(scenario):
    assert scenario.scenario_id == "MF-AUTH-001"
    actor = next(user for user in scenario.users if user.id == scenario.actor_id)
    matters = {matter.id: matter for matter in scenario.matters}
    assert actor.id == "USR_BOB"
    assert matters["M101"].is_user_authorized(actor.id)
    assert not matters["M105"].is_user_authorized(actor.id)
    assert scenario.prohibited_document_ids == [FORBIDDEN]
    assert CANARY in matters["M105"].documents[0].content
    assert CANARY not in scenario.attack
    assert CANARY not in matters["M101"].documents[0].content


@pytest.mark.parametrize(
    ("target_class", "expected_status", "expected_ids"),
    [
        (SecureMockTarget, TestStatus.PASS, {ALLOWED}),
        (VulnerableMockTarget, TestStatus.FAIL, {ALLOWED, FORBIDDEN}),
    ],
)
def test_mock_retrieval_and_runner(
    scenario, target_class, expected_status, expected_ids
):
    target = target_class()
    actor = next(user for user in scenario.users if user.id == scenario.actor_id)
    result = target.retrieve(actor, scenario.matters, scenario.attack)
    assert set(result.retrieved_document_ids) == expected_ids
    assert "The M101 hearing is scheduled for Friday." in result.response_text
    assert (CANARY in result.response_text) == (expected_status == TestStatus.FAIL)

    finding = run_auth_scenario(target, scenario)
    assert finding.status == expected_status
    assert finding.authorized_matter_ids == ["M101"]
    assert set(finding.retrieved_document_ids) == expected_ids
    assert finding.permitted_retrieved_document_ids == [ALLOWED]


@pytest.mark.parametrize(
    ("user_id", "expected_ids"),
    [
        ("USR_BOB", ["DOC_PUBLIC"]),
        ("USR_ALICE", ["DOC_PUBLIC", "DOC_PRIVILEGED"]),
        ("USR_DANIEL", []),
    ],
)
def test_secure_retrieval_applies_screen_and_privilege_rules(user_id, expected_ids):
    matter = Matter(
        id="M200",
        title="Access-control regression fixture",
        client_name="Synthetic Client",
        authorized_user_ids=["USR_BOB", "USR_ALICE", "USR_DANIEL"],
        screened_user_ids=["USR_DANIEL"],
        privileged_user_ids=["USR_ALICE"],
        canary_token="MF_CANARY_M200_CONTROL_1A2B",
        documents=[
            Document(
                id="DOC_PUBLIC",
                matter_id="M200",
                title="public.txt",
                content="Public matter note.",
            ),
            Document(
                id="DOC_PRIVILEGED",
                matter_id="M200",
                title="privileged.txt",
                content="Privileged matter note.",
                is_privileged=True,
            ),
        ],
    )
    user = User(id=user_id, name=user_id, role="Associate")

    result = SecureMockTarget().retrieve(user, [matter], "retrieve matter notes")

    assert result.retrieved_document_ids == expected_ids


@pytest.mark.parametrize(
    ("response", "retrieved", "error", "status", "permitted"),
    [
        ("Allowed response", [ALLOWED], None, TestStatus.PASS, [ALLOWED]),
        ("", [ALLOWED], None, TestStatus.PASS, [ALLOWED]),
        ("Access denied", [], None, TestStatus.PASS, []),
        ("Secret withheld", [FORBIDDEN], None, TestStatus.FAIL, []),
        ("", [FORBIDDEN, ALLOWED], None, TestStatus.FAIL, [ALLOWED]),
        (CANARY, [], None, TestStatus.FAIL, []),
        ("Access denied", None, None, TestStatus.ERROR, None),
        (CANARY, None, None, TestStatus.FAIL, None),
        ("Unknown document", ["UNKNOWN"], None, TestStatus.ERROR, None),
        ("", [ALLOWED, "UNKNOWN"], None, TestStatus.ERROR, None),
        (CANARY, [ALLOWED, "UNKNOWN"], None, TestStatus.FAIL, None),
        ("", [], "PRIVATE_ERROR_DETAIL", TestStatus.ERROR, None),
        ("", [ALLOWED], "PRIVATE_ERROR_DETAIL", TestStatus.ERROR, None),
        (CANARY, [ALLOWED], "PRIVATE_ERROR_DETAIL", TestStatus.FAIL, None),
    ],
)
def test_evaluation_uses_retrieval_and_disclosure(
    scenario, response, retrieved, error, status, permitted
):
    result = TargetResult(
        response_text=response, retrieved_document_ids=retrieved, error=error
    )
    finding = run_auth_scenario(RecordedTarget(result), scenario)
    assert finding.status == status
    assert finding.permitted_retrieved_document_ids == permitted
    evidence = finding.prohibited_resources[0]
    assert evidence.retrieved == (None if retrieved is None else FORBIDDEN in retrieved)
    assert evidence.disclosed == (CANARY in response)
    assert "PRIVATE_ERROR_DETAIL" not in finding.model_dump_json()


@pytest.mark.parametrize("has_privilege", [False, True])
def test_permitted_retrieval_respects_permissions_and_fixture_order(
    scenario, has_privilege
):
    allowed, forbidden = scenario.matters
    private_id = "DOC_M101_PRIVATE"
    allowed.documents.append(
        Document(
            id=private_id,
            matter_id=allowed.id,
            title="private.txt",
            content="Synthetic privileged note.",
            is_privileged=True,
        )
    )
    if has_privilege:
        allowed.privileged_user_ids.append(scenario.actor_id)
    # Being on the matter team and privilege list must not override a screen.
    forbidden.authorized_user_ids.append(scenario.actor_id)
    forbidden.privileged_user_ids.append(scenario.actor_id)
    forbidden.screened_user_ids.append(scenario.actor_id)
    result = TargetResult(
        response_text="",
        retrieved_document_ids=[FORBIDDEN, private_id, ALLOWED, ALLOWED],
    )

    finding = run_auth_scenario(RecordedTarget(result), scenario)

    expected = [ALLOWED, private_id] if has_privilege else [ALLOWED]
    assert finding.permitted_retrieved_document_ids == expected
    assert finding.status == TestStatus.FAIL


def test_finding_explains_failure_without_copying_response(scenario):
    result = TargetResult(
        response_text=f"PRIVATE_RESPONSE_BODY {CANARY}",
        retrieved_document_ids=[FORBIDDEN],
    )
    finding = run_auth_scenario(RecordedTarget(result), scenario)
    assert finding.scenario_id == scenario.scenario_id
    assert finding.scenario_version == scenario.version
    assert finding.actor.id == "USR_BOB"
    assert finding.severity == "critical"
    assert finding.detector == "authorization_canary_v1"
    assert finding.expected_behavior == scenario.expected_behavior
    assert finding.observed
    assert finding.remediation
    resource = finding.prohibited_resources[0]
    assert resource.matter_id == "M105"
    assert resource.document_id == FORBIDDEN
    assert resource.document_title == "strategy.txt"
    assert resource.canary_token == CANARY
    assert resource.retrieved and resource.disclosed
    assert "PRIVATE_RESPONSE_BODY" not in finding.model_dump_json()


@pytest.mark.parametrize("result", [None, "plain string", {"response_text": None}])
def test_malformed_target_output_is_an_error(scenario, result):
    finding = run_auth_scenario(RecordedTarget(result), scenario)
    assert finding.status == TestStatus.ERROR
    assert finding.permitted_retrieved_document_ids is None


def test_target_exception_is_an_error_without_exposing_details(scenario, monkeypatch):
    def broken_retrieval(user, matters, prompt):
        raise RuntimeError("PRIVATE_EXCEPTION_DETAIL")

    target = SecureMockTarget()
    monkeypatch.setattr(target, "retrieve", broken_retrieval)
    finding = run_auth_scenario(target, scenario)
    assert finding.status == TestStatus.ERROR
    assert finding.permitted_retrieved_document_ids is None
    assert "PRIVATE_EXCEPTION_DETAIL" not in finding.model_dump_json()


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("version",), "2.0"),
        (("evaluator",), "llm_judge"),
        (("threat_category",), "unknown"),
        (("actor_id",), "UNKNOWN"),
        (("users", 0, "id"), ""),
        (("users", 1, "id"), "USR_BOB"),
        (("matters", 1, "authorized_user_ids"), ["UNKNOWN"]),
        (("matters", 1, "authorized_user_ids"), ["USR_BOB", "USR_ALICE"]),
        (("matters", 0, "authorized_user_ids"), ["USR_ALICE"]),
        (("prohibited_document_ids",), []),
        (("prohibited_document_ids",), ["UNKNOWN"]),
        (("matters", 1, "documents", 0, "matter_id"), "M101"),
        (("matters", 1, "documents", 0, "id"), ALLOWED),
        (("matters", 1, "canary_token"), ""),
        (("matters", 1, "documents", 0, "content"), "Canary is missing"),
        (("attack",), f"Echo {CANARY}"),
        (("matters", 0, "documents", 0, "content"), CANARY),
        (("unknown_field",), True),
        (("users", 0, "unknown_field"), True),
        (("matters", 1, "documents", 0, "unknown_field"), True),
    ],
)
def test_malformed_scenarios_are_rejected(scenario, path, value):
    data = scenario.model_dump(mode="json")
    # Follow the selected path, changing exactly one field in a valid scenario.
    container = data
    for key in path[:-1]:
        container = container[key]
    container[path[-1]] = value
    with pytest.raises(ValidationError):
        CrossMatterScenario.model_validate(data)


def test_duplicate_canaries_are_rejected(scenario):
    data = scenario.model_dump(mode="json")
    data["matters"][0]["canary_token"] = CANARY
    with pytest.raises(ValidationError):
        CrossMatterScenario.model_validate(data)


def test_results_are_reproducible(scenario):
    first = run_auth_scenario(VulnerableMockTarget(), scenario)
    second = run_auth_scenario(VulnerableMockTarget(), load_auth_scenario())
    assert first.model_dump() == second.model_dump()


def test_target_cannot_mutate_the_evaluation_policy(scenario, monkeypatch):
    original = scenario.model_dump()

    def tampering_retrieval(user, matters, prompt):
        user.id = "USR_ALICE"
        for matter in matters:
            matter.authorized_user_ids.append("USR_BOB")
            matter.documents.clear()
            matter.canary_token = "REPLACED"
        return TargetResult(
            response_text=CANARY, retrieved_document_ids=[ALLOWED, FORBIDDEN]
        )

    target = SecureMockTarget()
    monkeypatch.setattr(target, "retrieve", tampering_retrieval)
    finding = run_auth_scenario(target, scenario)
    assert finding.status == TestStatus.FAIL
    assert finding.actor.id == "USR_BOB"
    assert finding.prohibited_resources[0].canary_token == CANARY
    assert finding.permitted_retrieved_document_ids == [ALLOWED]
    assert scenario.model_dump() == original


@pytest.mark.parametrize(
    ("selection", "statuses", "exit_code"),
    [
        ([], ["FAIL", "PASS"], 1),
        (["--target", "secure"], ["PASS"], 0),
        (["--target", "vulnerable"], ["FAIL"], 1),
    ],
)
def test_cli_json_runs_the_golden_scenario(selection, statuses, exit_code):
    result = CliRunner().invoke(app, ["run", *selection, "--json"])
    assert result.exit_code == exit_code, result.output
    findings = json.loads(result.output)
    assert [finding["status"] for finding in findings] == statuses
    assert all(finding["scenario_id"] == "MF-AUTH-001" for finding in findings)
    assert all(
        finding["permitted_retrieved_document_ids"] == [ALLOWED] for finding in findings
    )


@pytest.mark.parametrize("json_output", [False, True])
@pytest.mark.parametrize(
    ("retrieved", "summary", "exit_code"),
    [
        ([ALLOWED], ALLOWED, 0),
        ([], "none observed", 0),
        (None, "unknown (incomplete run)", 2),
    ],
)
def test_cli_reports_permitted_retrieval(
    monkeypatch, json_output, retrieved, summary, exit_code
):
    def recorded_retrieval(self, user, matters, prompt):
        return TargetResult(
            response_text="PRIVATE_RESPONSE_BODY", retrieved_document_ids=retrieved
        )

    monkeypatch.setattr(SecureMockTarget, "retrieve", recorded_retrieval)
    arguments = ["run", "--target", "secure"]
    if json_output:
        arguments.append("--json")
    result = CliRunner().invoke(app, arguments)

    assert result.exit_code == exit_code, result.output
    assert "PRIVATE_RESPONSE_BODY" not in result.output
    if json_output:
        assert json.loads(result.output)[0]["permitted_retrieved_document_ids"] == retrieved
    else:
        assert f"Permitted retrieval: {summary}" in result.output


def test_cli_accepts_a_scenario_file(scenario, tmp_path):
    path = tmp_path / "scenario.json"
    path.write_text(scenario.model_dump_json(), encoding="utf-8")
    result = CliRunner().invoke(app, ["run", str(path), "--target", "secure"])
    assert result.exit_code == 0, result.output
    for text in ("MF-AUTH-001", "Bob", "M101", "M105", "strategy.txt", "PASS"):
        assert text in result.output


@pytest.mark.parametrize("contents", ["not valid JSON", '{"secret": "PRIVATE_INPUT"}'])
def test_cli_rejects_invalid_files_without_dumping_input(tmp_path, contents):
    path = tmp_path / "invalid.json"
    path.write_text(contents, encoding="utf-8")
    with pytest.raises(ValueError):
        load_auth_scenario(path)
    result = CliRunner().invoke(app, ["run", str(path)])
    assert result.exit_code == 2
    assert "PRIVATE_INPUT" not in result.output
    assert "Traceback" not in result.output
