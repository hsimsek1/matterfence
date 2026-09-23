import json
from html import escape
from html.parser import HTMLParser

import pytest
from typer.testing import CliRunner

from matterfence import cli
from matterfence.core.runner import Finding, TestStatus, run_auth_scenario
from matterfence.core.scenario import load_auth_scenario
from matterfence.report import render_report, write_report
from matterfence.targets.mock import (
    SecureMockTarget,
    TargetResult,
    VulnerableMockTarget,
)

WRITE_ERROR = (
    "Unable to write HTML report. "
    "Use a new path in an existing writable folder."
)


class ReportParser(HTMLParser):
    """Inspect rendered text and markup without depending on the visual layout."""

    def __init__(self, html):
        super().__init__()
        self.tags = []
        self.attributes = []
        self.text = []
        self.hidden_depth = 0
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)
        if tag in {"head", "style", "script"}:
            self.hidden_depth += 1

    def handle_endtag(self, tag):
        if tag in {"head", "style", "script"}:
            self.hidden_depth -= 1

    def handle_data(self, data):
        if self.hidden_depth == 0:
            self.text.append(data)


@pytest.fixture
def findings():
    scenario = load_auth_scenario()
    return [
        run_auth_scenario(VulnerableMockTarget(), scenario),
        run_auth_scenario(SecureMockTarget(), scenario),
    ]


def test_render_is_deterministic_and_does_not_change_or_execute_findings(
    findings, monkeypatch, tmp_path
):
    originals = [finding.model_dump() for finding in findings]

    def unexpected_execution(*args, **kwargs):
        pytest.fail("Formatting findings must not execute another evaluation.")

    monkeypatch.setattr(SecureMockTarget, "retrieve", unexpected_execution)
    monkeypatch.setattr(VulnerableMockTarget, "retrieve", unexpected_execution)
    monkeypatch.chdir(tmp_path)

    html = render_report(findings)

    assert html == render_report(findings)
    assert [finding.model_dump() for finding in findings] == originals
    assert list(tmp_path.iterdir()) == []
    parsed = ReportParser(html)
    assert {"html", "head", "title", "body", "style"} <= set(parsed.tags)
    text = " ".join(parsed.text)
    for expected in (
        "MatterFence", "VulnerableMockTarget", "SecureMockTarget", "FAIL", "PASS",
        "MF-AUTH-001", "Bob", "Associate", "USR_BOB", "M101", "M105",
        "DOC_M101_TIMELINE", "DOC_M105_STRATEGY", "strategy.txt",
        "MF_CANARY_M105_PRIVILEGED_7C91", "Yes", "No",
    ):
        assert expected in text


def test_every_free_text_field_is_visible_but_cannot_become_active_html(findings):
    data = findings[0].model_dump()
    payloads = []

    def payload(field):
        value = f'{field}: <img src="https://attacker.invalid/x" onerror="alert(1)"> & \' '
        payloads.append(value)
        return value

    for field in (
        "scenario_id", "scenario_version", "target_name", "severity", "detector",
        "expected_behavior", "observed", "remediation",
    ):
        data[field] = payload(field)
    for field in ("id", "name", "role"):
        data["actor"][field] = payload(f"actor.{field}")
    for field in (
        "authorized_matter_ids", "retrieved_document_ids",
        "permitted_retrieved_document_ids",
    ):
        data[field] = [payload(field)]
    for field in ("matter_id", "document_id", "document_title", "canary_token"):
        data["prohibited_resources"][0][field] = payload(f"resource.{field}")

    html = render_report([Finding.model_validate(data)])
    parsed = ReportParser(html)
    visible_text = "".join(parsed.text)
    for value in payloads:
        assert escape(value) in html
        assert value in visible_text
    assert not {"script", "iframe", "object", "embed", "img", "link", "base"}.intersection(
        parsed.tags
    )
    for name, value in parsed.attributes:
        assert not name.lower().startswith("on")
        assert name not in {"src", "href", "action", "formaction", "srcdoc"}
        assert "attacker.invalid" not in (value or "")
    assert "@import" not in html
    assert "url(" not in html


@pytest.mark.parametrize(
    ("ids", "label", "status"),
    [
        (None, "Unknown (incomplete run)", TestStatus.ERROR),
        ([], "None observed", TestStatus.PASS),
        (["TRACE_ONLY_DOCUMENT"], "TRACE_ONLY_DOCUMENT", TestStatus.PASS),
    ],
)
def test_report_distinguishes_missing_empty_and_present_trace(findings, ids, label, status):
    finding = findings[1]
    finding.status = status
    finding.retrieved_document_ids = ids
    finding.permitted_retrieved_document_ids = ids
    finding.prohibited_resources[0].retrieved = None if ids is None else False

    parsed = ReportParser(render_report([finding]))

    assert " ".join(parsed.text).count(label) >= 2
    assert status.value in parsed.text


def test_known_disclosure_remains_failure_when_retrieval_is_unknown(monkeypatch):
    scenario = load_auth_scenario()
    target = SecureMockTarget()

    def incomplete_retrieval(user, matters, prompt):
        return TargetResult(
            response_text=scenario.matters[1].canary_token,
            retrieved_document_ids=None,
        )

    monkeypatch.setattr(target, "retrieve", incomplete_retrieval)
    finding = run_auth_scenario(target, scenario)

    parsed = ReportParser(render_report([finding]))

    assert "FAIL" in parsed.text
    assert "Unknown" in parsed.text
    assert "Yes" in parsed.text
    assert "Unknown (incomplete run)" in parsed.text
    assert "Retrieval observations are unavailable." in " ".join(parsed.text)


def test_all_prohibited_resources_are_rendered(findings):
    finding = findings[0]
    second = finding.prohibited_resources[0].model_copy(deep=True)
    second.document_id = "SECOND_FORBIDDEN_DOCUMENT"
    second.document_title = "Second evidence item"
    finding.prohibited_resources.append(second)

    html = render_report([finding])

    assert "DOC_M105_STRATEGY" in html
    assert second.document_id in html
    assert second.document_title in html


def test_interpretation_limits_remain_visible_for_all_statuses(findings):
    incomplete = findings[1].model_copy(deep=True)
    incomplete.status = TestStatus.ERROR
    incomplete.retrieved_document_ids = None
    incomplete.permitted_retrieved_document_ids = None
    parsed = ReportParser(render_report([*findings, incomplete]))
    text = " ".join(" ".join(parsed.text).split())

    assert "No violation observed in this run." in text
    assert "Incomplete evidence. This is not a pass." in text
    assert "A known violation remains FAIL even when other evidence is incomplete." in text
    assert "not a security guarantee or legal compliance determination." in text
    assert "Permitted IDs do not establish answer quality or relevance." in text
    assert "A matter canary can be shared by several documents;" in text
    assert "its disclosure does not identify a unique source document." in text


def test_empty_findings_are_rejected_without_creating_a_file(tmp_path):
    path = tmp_path / "empty.html"
    with pytest.raises(ValueError):
        render_report([])
    with pytest.raises(ValueError):
        write_report([], path)
    assert not path.exists()


def test_write_report_creates_utf8_once_without_overwriting(findings, tmp_path):
    findings[0].actor.name = "Zoë — synthetic reviewer"
    path = tmp_path / "evidence report.html"

    assert write_report(findings, path) is None
    assert path.read_text(encoding="utf-8") == render_report(findings)
    original = path.read_bytes()

    with pytest.raises(FileExistsError):
        write_report(findings[1:], path)
    assert path.read_bytes() == original


@pytest.mark.parametrize(
    ("selection", "statuses", "exit_code"),
    [
        ([], ["FAIL", "PASS"], 1),
        (["--target", "secure"], ["PASS"], 0),
        (["--target", "vulnerable"], ["FAIL"], 1),
    ],
)
@pytest.mark.parametrize("json_output", [False, True])
def test_cli_report_preserves_findings_and_does_not_evaluate_twice(
    tmp_path, monkeypatch, selection, statuses, exit_code, json_output
):
    calls = []

    def counted_run(target, scenario):
        calls.append(target.__class__.__name__)
        return run_auth_scenario(target, scenario)

    monkeypatch.setattr(cli, "run_auth_scenario", counted_run)
    path = tmp_path / "report with spaces.html"
    args = ["run", *selection, "--report", str(path)]
    if json_output:
        args.append("--json")

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == exit_code, result.output
    assert len(calls) == len(statuses)
    assert result.stderr.strip() == "HTML report saved."
    assert "HTML report saved." not in result.stdout
    text = " ".join(ReportParser(path.read_text(encoding="utf-8")).text)
    for status in statuses:
        assert status in text
    if json_output:
        assert [item["status"] for item in json.loads(result.stdout)] == statuses
    else:
        for status in statuses:
            assert f"Result: {status}" in result.stdout


def test_cli_error_report_excludes_raw_target_response_and_error(tmp_path, monkeypatch):
    def incomplete_retrieval(self, user, matters, prompt):
        return TargetResult(
            response_text="PRIVATE_RAW_ANSWER",
            error="PRIVATE_TARGET_ERROR",
        )

    monkeypatch.setattr(SecureMockTarget, "retrieve", incomplete_retrieval)
    path = tmp_path / "error.html"
    result = CliRunner().invoke(
        cli.app, ["run", "--target", "secure", "--json", "--report", str(path)]
    )

    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)[0]["status"] == "ERROR"
    html = path.read_text(encoding="utf-8")
    assert "ERROR" in html
    assert "Unknown (incomplete run)" in html
    for secret in (
        "PRIVATE_RAW_ANSWER", "PRIVATE_TARGET_ERROR",
        "The M101 hearing is scheduled for Friday.",
    ):
        assert secret not in html
        assert secret not in result.output


@pytest.mark.parametrize("destination", ["existing", "scenario", "directory", "missing"])
def test_cli_write_failure_preserves_output_and_existing_files(tmp_path, destination):
    scenario = tmp_path / "scenario.json"
    scenario.write_text(load_auth_scenario().model_dump_json(), encoding="utf-8")
    paths = {
        "existing": tmp_path / "existing.html",
        "scenario": scenario,
        "directory": tmp_path,
        "missing": tmp_path / "missing" / "report.html",
    }
    paths["existing"].write_text("KEEP THIS REPORT", encoding="utf-8")
    originals = {path: path.read_bytes() for path in (scenario, paths["existing"])}
    result = CliRunner().invoke(
        cli.app,
        [
            "run", str(scenario), "--target", "secure", "--json",
            "--report", str(paths[destination]),
        ],
    )

    assert result.exit_code == 2, result.output
    assert json.loads(result.stdout)[0]["status"] == "PASS"
    assert result.stderr.strip() == WRITE_ERROR
    assert str(tmp_path) not in result.output
    for path, contents in originals.items():
        assert path.read_bytes() == contents
    assert not paths["missing"].exists()


@pytest.mark.parametrize("error_type", [PermissionError, ValueError])
def test_cli_redacts_writer_errors(tmp_path, monkeypatch, error_type):
    def denied_write(findings, path):
        raise error_type("PRIVATE_FILESYSTEM_DETAIL")

    monkeypatch.setattr(cli, "write_report", denied_write)
    result = CliRunner().invoke(
        cli.app,
        ["run", "--target", "secure", "--json", "--report", str(tmp_path / "out.html")],
    )

    assert result.exit_code == 2
    assert json.loads(result.stdout)[0]["status"] == "PASS"
    assert result.stderr.strip() == WRITE_ERROR
    assert "PRIVATE_FILESYSTEM_DETAIL" not in result.output


@pytest.mark.parametrize("invalid_input", ["scenario", "target"])
def test_invalid_inputs_do_not_create_reports(tmp_path, invalid_input):
    path = tmp_path / "report.html"
    args = ["run", "--report", str(path)]
    if invalid_input == "scenario":
        scenario = tmp_path / "invalid.json"
        scenario.write_text("not JSON", encoding="utf-8")
        args.append(str(scenario))
    else:
        args.extend(["--target", "http"])

    result = CliRunner().invoke(cli.app, args)

    assert result.exit_code == 2
    assert not path.exists()
