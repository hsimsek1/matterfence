import json
from http.client import HTTPConnection
from threading import Thread

import httpx
import pytest
from typer.testing import CliRunner

from examples.retrieval_case_study import (
    RESULT_LIMIT,
    build_store,
    create_server,
    retrieve,
)
from matterfence.cli import app
from matterfence.core.runner import TestStatus, run_auth_scenario
from matterfence.core.scenario import load_auth_scenario
from matterfence.report import render_report
from matterfence.targets.http import HttpLegalTarget

ALLOWED = "DOC_M101_TIMELINE"
FORBIDDEN = "DOC_M105_STRATEGY"


@pytest.fixture
def scenario():
    return load_auth_scenario()


@pytest.fixture
def store_factory(scenario):
    stores = []

    def build(fixture=None):
        store = build_store(scenario.model_dump() if fixture is None else fixture)
        stores.append(store)
        return store

    yield build
    for store in stores:
        store.close()


@pytest.fixture
def server_factory(store_factory):
    running = []

    def start(mode="secure"):
        server = create_server(store_factory(), mode=mode, port=0)
        assert server.server_address[0] == "127.0.0.1"
        thread = Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        )
        thread.start()
        running.append((server, thread))
        return f"http://127.0.0.1:{server.server_port}/retrieve"

    yield start
    for server, thread in running:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        assert not thread.is_alive()


@pytest.mark.parametrize(
    ("mode", "status", "exit_code", "expected_ids"),
    [
        ("vulnerable", TestStatus.FAIL, 1, {ALLOWED, FORBIDDEN}),
        ("secure", TestStatus.PASS, 0, {ALLOWED}),
    ],
)
def test_real_http_failure_fix_and_report(
    server_factory, scenario, tmp_path, mode, status, exit_code, expected_ids
):
    endpoint = server_factory(mode)
    target = HttpLegalTarget(endpoint)
    actor = next(user for user in scenario.users if user.id == scenario.actor_id)

    # No evaluator documents or permissions are sent to the independent store.
    observation = target.retrieve(actor, [], scenario.attack)
    documents = {
        doc.id: doc for matter in scenario.matters for doc in matter.documents
    }
    assert set(observation.retrieved_document_ids) == expected_ids
    assert observation.response_text == "\n".join(
        documents[doc_id].content for doc_id in observation.retrieved_document_ids
    )
    assert observation.error is None

    finding = run_auth_scenario(target, scenario)
    assert finding.status == status
    assert set(finding.retrieved_document_ids) == expected_ids
    assert finding.permitted_retrieved_document_ids == [ALLOWED]
    evidence, = finding.prohibited_resources
    assert evidence.retrieved is (mode == "vulnerable")
    assert evidence.disclosed is (mode == "vulnerable")

    report = tmp_path / f"{mode}.html"
    result = CliRunner().invoke(
        app,
        [
            "run", "--target", "http", "--endpoint", endpoint,
            "--json", "--report", str(report),
        ],
    )
    assert result.exit_code == exit_code, result.output
    assert json.loads(result.stdout) == [finding.model_dump(mode="json")]
    assert report.read_text(encoding="utf-8") == render_report([finding])


@pytest.mark.parametrize(
    ("user_id", "prompt", "mode", "expected_ids"),
    [
        ("USR_BOB", "hearing", "secure", [ALLOWED]),
        ("USR_BOB", "timelines", "secure", [ALLOWED]),
        ("USR_BOB", "negotiation", "secure", []),
        ("USR_BOB", "negotiation", "vulnerable", [FORBIDDEN]),
        ("USR_ALICE", "negotiation", "secure", [FORBIDDEN]),
        ("USR_BOB", "unmatchablezz", "secure", []),
        ("USR_BOB", "() : * + -", "secure", []),
        ("USR_BOB", "", "secure", []),
        ("USR_BOB", '"strategy" OR (nothing*)', "vulnerable", [FORBIDDEN]),
    ],
)
def test_search_selects_matches_and_quotes_query_syntax(
    store_factory, user_id, prompt, mode, expected_ids
):
    result = retrieve(store_factory(), user_id, prompt, mode=mode)

    assert result["retrieved_document_ids"] == expected_ids
    assert result["error"] is None
    if not expected_ids:
        assert result["response_text"] == ""


@pytest.mark.parametrize(
    ("authorized", "screened", "privileged", "document_privileged", "allowed"),
    [
        (False, False, True, True, False),
        (True, False, False, True, False),
        (True, False, True, True, True),
        (True, True, True, True, False),
        (True, True, False, False, False),
        (True, False, False, False, True),
    ],
)
def test_permissions_apply_before_content_is_returned(
    store_factory, scenario, authorized, screened, privileged,
    document_privileged, allowed,
):
    fixture = scenario.model_dump()
    restricted = fixture["matters"][1]
    restricted["authorized_user_ids"] = ["USR_BOB"] if authorized else []
    restricted["screened_user_ids"] = ["USR_BOB"] if screened else []
    restricted["privileged_user_ids"] = ["USR_BOB"] if privileged else []
    restricted["documents"][0]["is_privileged"] = document_privileged

    result = retrieve(store_factory(fixture), "USR_BOB", "strategy")

    assert result["retrieved_document_ids"] == ([FORBIDDEN] if allowed else [])
    assert (restricted["canary_token"] in result["response_text"]) is allowed


def test_permission_filter_precedes_result_limit(store_factory, scenario):
    fixture = scenario.model_dump()
    readable, restricted = fixture["matters"]
    readable["documents"][0]["content"] = "needle " + "background " * 100
    restricted["documents"] = [
        {
            "id": f"BLOCKED_{index}", "matter_id": restricted["id"],
            "title": "needle", "content": "needle", "is_privileged": True,
        }
        for index in range(RESULT_LIMIT + 1)
    ]
    store = store_factory(fixture)

    vulnerable = retrieve(store, "USR_BOB", "needle", mode="vulnerable")
    secure = retrieve(store, "USR_BOB", "needle")

    assert len(vulnerable["retrieved_document_ids"]) == RESULT_LIMIT
    assert ALLOWED not in vulnerable["retrieved_document_ids"]
    assert secure["retrieved_document_ids"] == [ALLOWED]
    assert secure["response_text"] == readable["documents"][0]["content"]


@pytest.mark.parametrize("mode", ["secure", "vulnerable"])
def test_unknown_identity_cannot_search_even_in_vulnerable_mode(store_factory, mode):
    with pytest.raises(PermissionError):
        retrieve(store_factory(), "UNKNOWN", "strategy", mode=mode)


def test_unsupported_mode_does_not_silently_disable_permissions(store_factory):
    store = store_factory()
    with pytest.raises(ValueError):
        retrieve(store, "USR_BOB", "strategy", mode="typo")
    with pytest.raises(ValueError):
        create_server(store, mode="typo", port=0)


def test_search_term_limit_rejects_excess_without_truncating(store_factory):
    store = store_factory()
    prompt = " ".join(f"unmatched{index}" for index in range(64))
    assert retrieve(store, "USR_BOB", prompt)["retrieved_document_ids"] == []
    with pytest.raises(ValueError):
        retrieve(store, "USR_BOB", prompt + " strategy")


@pytest.mark.parametrize(
    ("payload", "path", "expected_status"),
    [
        ({"user_id": "UNKNOWN", "prompt": "PRIVATE_INPUT"}, "/retrieve", 403),
        ({"user_id": "USR_BOB", "prompt": "PRIVATE_INPUT",
          "authorized_user_ids": ["USR_BOB"]}, "/retrieve", 400),
        ({"user_id": "USR_BOB", "prompt": 7}, "/retrieve", 400),
        ({"user_id": "USR_BOB"}, "/retrieve", 400),
        ([], "/retrieve", 400),
        ({"user_id": "USR_BOB", "prompt": "PRIVATE_INPUT"}, "/unknown", 404),
    ],
)
def test_http_rejects_invalid_requests_without_disclosure(
    server_factory, scenario, payload, path, expected_status
):
    base_url = server_factory().removesuffix("/retrieve")
    with httpx.Client(timeout=2, trust_env=False) as client:
        response = client.post(base_url + path, json=payload)

    assert response.status_code == expected_status
    for secret in ("PRIVATE_INPUT", scenario.matters[1].canary_token, "Traceback"):
        assert secret not in response.text


def test_http_rejects_malformed_json(server_factory):
    with httpx.Client(timeout=2, trust_env=False) as client:
        response = client.post(
            server_factory(), content=b"PRIVATE_INVALID_JSON",
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 400
    assert "PRIVATE_INVALID_JSON" not in response.text


def test_http_rejects_oversized_numeric_length_without_parsing_it(server_factory):
    port = httpx.URL(server_factory()).port
    connection = HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        connection.request(
            "POST", "/retrieve",
            headers={"Content-Type": "application/json", "Content-Length": "9" * 5000},
        )
        response = connection.getresponse()
        body = response.read().decode("utf-8")
    finally:
        connection.close()

    assert response.status == 400
    assert "Traceback" not in body
    assert "9" * 5000 not in body
    assert json.loads(body)["response_text"] == ""


@pytest.mark.parametrize("path", ["/", "/retrieve"])
def test_browser_info_does_not_serve_documents(server_factory, scenario, path):
    base_url = server_factory().removesuffix("/retrieve")
    with httpx.Client(timeout=2, trust_env=False) as client:
        response = client.get(base_url + path)

    assert response.status_code == 200
    assert response.json()["mode"] == "secure"
    assert "/retrieve" in response.json()["message"]
    for matter in scenario.matters:
        assert matter.canary_token not in response.text
        for document in matter.documents:
            assert document.content not in response.text
