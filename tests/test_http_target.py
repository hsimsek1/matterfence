import gzip
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import httpx
import pytest
from typer.testing import CliRunner

from matterfence.cli import app
from matterfence.core.runner import TestStatus, run_auth_scenario
from matterfence.core.scenario import load_auth_scenario
from matterfence.targets.http import (
    MAX_RESPONSE_BYTES,
    TIMEOUT_SECONDS,
    HttpLegalTarget,
)

ALLOWED = "DOC_M101_TIMELINE"
FORBIDDEN = "DOC_M105_STRATEGY"
CANARY = "MF_CANARY_M105_PRIVILEGED_7C91"


@pytest.fixture
def http_server():
    """Serve one configurable response and record requests on a local random port."""
    requests = []
    response = {
        "status": 200,
        "body": json.dumps(
            {"response_text": "Allowed note", "retrieved_document_ids": [ALLOWED]}
        ).encode(),
    }

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            requests.append((self.command, self.path, dict(self.headers), body))
            self.send_response(response["status"])
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response["body"])))
            if "encoding" in response:
                self.send_header("Content-Encoding", response["encoding"])
            self.send_header("Location", "/redirected")
            self.end_headers()
            self.wfile.write(response["body"])

        do_GET = do_POST

        def log_message(self, format, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/retrieve", requests, response
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_request_sends_only_actor_and_prompt(http_server):
    endpoint, requests, _ = http_server
    scenario = load_auth_scenario()
    actor = next(user for user in scenario.users if user.id == scenario.actor_id)

    result = HttpLegalTarget(endpoint).retrieve(
        actor, scenario.matters, scenario.attack
    )

    assert result.response_text == "Allowed note"
    assert result.retrieved_document_ids == [ALLOWED]
    assert len(requests) == 1
    method, path, headers, body = requests[0]
    assert (method, path) == ("POST", "/retrieve")
    assert headers["Content-Type"] == "application/json"
    assert headers["Accept"] == "application/json"
    assert headers["Accept-Encoding"] == "identity"
    assert json.loads(body) == {"user_id": "USR_BOB", "prompt": scenario.attack}
    assert CANARY.encode() not in body


@pytest.mark.parametrize(
    ("text", "ids", "status", "exit_code"),
    [
        ("Allowed note", [ALLOWED], "PASS", 0),
        ("Withheld", [FORBIDDEN], "FAIL", 1),
        (CANARY, [], "FAIL", 1),
        ("Unknown trace", None, "ERROR", 2),
        ("Unknown record", ["UNKNOWN"], "ERROR", 2),
    ],
)
def test_cli_evaluates_http_observations(http_server, text, ids, status, exit_code):
    endpoint, _, response = http_server
    response["body"] = json.dumps(
        {"response_text": text, "retrieved_document_ids": ids}
    ).encode()

    result = CliRunner().invoke(
        app, ["run", "--target", "http", "--endpoint", endpoint, "--json"]
    )

    assert result.exit_code == exit_code, result.output
    finding, = json.loads(result.output)
    assert finding["target_name"] == "HttpLegalTarget"
    assert finding["status"] == status
    assert finding["retrieved_document_ids"] == ids
    evidence, = finding["prohibited_resources"]
    assert evidence["retrieved"] == (None if ids is None else FORBIDDEN in ids)
    assert evidence["disclosed"] == (CANARY in text)


@pytest.mark.parametrize(
    "body",
    [
        b"PRIVATE_INVALID_JSON",
        b"[]",
        b"null",
        b'{"retrieved_document_ids": []}',
        b'{"response_text": "PRIVATE_BODY", "retrieved_document_ids": "bad"}',
        b'{"response_text": "PRIVATE_BODY", "unexpected": true}',
    ],
)
def test_invalid_response_is_an_error_without_body_disclosure(http_server, body):
    endpoint, _, response = http_server
    response["body"] = body

    finding = run_auth_scenario(HttpLegalTarget(endpoint), load_auth_scenario())

    assert finding.status == TestStatus.ERROR
    assert "PRIVATE" not in finding.model_dump_json()


@pytest.mark.parametrize("canary", ["", CANARY])
def test_application_error_is_redacted_without_hiding_disclosure(http_server, canary):
    endpoint, _, response = http_server
    response["body"] = json.dumps(
        {"response_text": f"PRIVATE_BODY {canary}", "error": "PRIVATE_SERVER_ERROR"}
    ).encode()

    finding = run_auth_scenario(HttpLegalTarget(endpoint), load_auth_scenario())

    assert finding.status == (TestStatus.FAIL if canary else TestStatus.ERROR)
    assert "PRIVATE" not in finding.model_dump_json()


@pytest.mark.parametrize("status", [302, 403, 500])
def test_http_errors_and_redirects_are_not_followed(http_server, status):
    endpoint, requests, response = http_server
    response.update(status=status, body=b"PRIVATE_ERROR_BODY")

    finding = run_auth_scenario(HttpLegalTarget(endpoint), load_auth_scenario())

    assert finding.status == TestStatus.ERROR
    assert len(requests) == 1
    assert "PRIVATE" not in finding.model_dump_json()


@pytest.mark.parametrize("error_class", [httpx.ReadTimeout, httpx.ConnectError])
def test_transport_failures_preserve_errors_and_safe_options(monkeypatch, error_class):
    options = {}

    def broken_stream(*args, **kwargs):
        options.update(kwargs)
        raise error_class("PRIVATE_CONNECTION_DETAIL")

    monkeypatch.setattr("matterfence.targets.http.httpx.stream", broken_stream)
    finding = run_auth_scenario(
        HttpLegalTarget("http://127.0.0.1:8000/retrieve"), load_auth_scenario()
    )

    assert finding.status == TestStatus.ERROR
    assert "PRIVATE" not in finding.model_dump_json()
    assert options["timeout"] == TIMEOUT_SECONDS
    assert options["follow_redirects"] is False
    assert options["trust_env"] is False


def test_compressed_response_is_rejected_before_parsing(http_server):
    endpoint, _, response = http_server
    # Valid observations would pass if the adapter decompressed this body.
    response.update(encoding="gzip", body=gzip.compress(response["body"]))

    finding = run_auth_scenario(HttpLegalTarget(endpoint), load_auth_scenario())

    assert finding.status == TestStatus.ERROR


@pytest.mark.parametrize("extra_bytes", [0, 1])
def test_response_byte_limit(http_server, extra_bytes):
    endpoint, _, response = http_server
    # Trailing JSON whitespace makes a valid response exactly the selected size.
    body = response["body"]
    response["body"] = body + b" " * (MAX_RESPONSE_BYTES + extra_bytes - len(body))

    finding = run_auth_scenario(HttpLegalTarget(endpoint), load_auth_scenario())

    assert finding.status == (TestStatus.ERROR if extra_bytes else TestStatus.PASS)


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://127.0.0.1/retrieve",
        "http://localhost/retrieve",
        "http://example.com/retrieve",
        "http://127.0.0.1.example.com/retrieve",
        "file:///tmp/records.json",
        "http://user:PRIVATE_PASSWORD@127.0.0.1/retrieve",
        "http://127.0.0.1/retrieve?secret=PRIVATE_VALUE",
        "http://127.0.0.1/retrieve#PRIVATE_FRAGMENT",
        "http://127.0.0.1:PRIVATE_BAD_PORT/retrieve",
        "http://127.0.0.1/\nPRIVATE_PATH",
        "not a URL",
    ],
)
def test_invalid_endpoints_are_rejected_safely(endpoint):
    with pytest.raises(ValueError) as caught:
        HttpLegalTarget(endpoint)
    assert "PRIVATE" not in str(caught.value)


def test_ipv6_loopback_endpoint_is_accepted():
    HttpLegalTarget("http://[::1]:8000/retrieve")


def test_text_output_identifies_the_http_target(http_server):
    endpoint, _, _ = http_server

    result = CliRunner().invoke(
        app, ["run", "--target", "http", "--endpoint", endpoint]
    )

    assert result.exit_code == 0, result.output
    assert "(HTTP target)" in result.output
    assert "HttpLegalTarget" in result.output
    assert "mock targets" not in result.output


def test_legacy_methods_are_explicitly_unsupported():
    target = HttpLegalTarget("http://127.0.0.1:8000/retrieve")
    scenario = load_auth_scenario()
    user, matter = scenario.users[0], scenario.matters[0]

    with pytest.raises(NotImplementedError):
        target.query_matter(user, matter, "Request")
    with pytest.raises(NotImplementedError):
        target.summarize_document(user, matter.documents[0], matter)


@pytest.mark.parametrize(
    "options",
    [
        ["--target", "http"],
        ["--target", "secure", "--endpoint", "http://127.0.0.1:8000"],
        ["--endpoint", "http://127.0.0.1:8000"],
        ["--target", "http", "--endpoint", "http://example.com"],
    ],
)
def test_invalid_cli_options_do_not_contact_a_server(monkeypatch, options):
    calls = []

    def unexpected_stream(*args, **kwargs):
        calls.append(args)
        raise RuntimeError("Unexpected network request")

    monkeypatch.setattr("matterfence.targets.http.httpx.stream", unexpected_stream)
    result = CliRunner().invoke(app, ["run", *options])

    assert result.exit_code == 2, result.output
    assert not calls
