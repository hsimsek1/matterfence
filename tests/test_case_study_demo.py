import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from examples import run_case_study as demo
from matterfence.core.runner import Finding, TestStatus, run_auth_scenario
from matterfence.core.scenario import load_auth_scenario
from matterfence.report import render_report
from matterfence.targets.mock import SecureMockTarget


@pytest.fixture
def resources(monkeypatch):
    """Observe real resources without replacing SQLite, HTTP, or the evaluator."""
    tracked = {"stores": [], "servers": [], "threads": [], "fixtures": []}
    build_store, create_server, thread_type = (
        demo.build_store, demo.create_server, demo.Thread,
    )

    def build(fixture):
        tracked["fixtures"].append(fixture)
        store = build_store(fixture)
        tracked["stores"].append(store)
        return store

    def serve(*args, **kwargs):
        server = create_server(*args, **kwargs)
        tracked["servers"].append(server)
        return server

    def thread(*args, **kwargs):
        worker = thread_type(*args, **kwargs)
        tracked["threads"].append(worker)
        return worker

    monkeypatch.setattr(demo, "build_store", build)
    monkeypatch.setattr(demo, "create_server", serve)
    monkeypatch.setattr(demo, "Thread", thread)
    return tracked


def assert_closed(resources):
    assert all(not thread.is_alive() for thread in resources["threads"])
    assert all(server.fileno() == -1 for server in resources["servers"])
    for store in resources["stores"]:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            store.execute("SELECT 1")


@pytest.mark.parametrize(
    ("case", "scenario_id", "permitted"),
    [
        ("authorization", "MF-AUTH-001", "DOC_M101_TIMELINE"),
        ("exhibit", "MF-INJECT-001-RETRIEVAL", "DOC_M101_EXHIBIT"),
    ],
)
def test_comparison_real_http_evidence_and_cleanup(
    tmp_path, resources, case, scenario_id, permitted,
):
    output_dir = tmp_path / "nested" / case
    findings = demo.run_comparison(case, output_dir)
    assert [item.status for item in findings] == [TestStatus.FAIL, TestStatus.PASS]
    assert [item.target_name for item in findings] == [
        "SQLite vulnerable (HTTP)", "SQLite secure (HTTP)",
    ]
    for index, finding in enumerate(findings):
        assert finding.scenario_id == scenario_id
        assert finding.permitted_retrieved_document_ids == [permitted]
        assert set(finding.retrieved_document_ids) == (
            {permitted, "DOC_M105_STRATEGY"} if index == 0 else {permitted}
        )
        resource, = finding.prohibited_resources
        assert resource.retrieved is (index == 0)
        assert resource.disclosed is (index == 0)
    raw_json = (output_dir / "findings.json").read_text(encoding="utf-8")
    assert [Finding.model_validate(item) for item in json.loads(raw_json)] == findings
    html = (output_dir / "comparison.html").read_text(encoding="utf-8")
    assert html == render_report(findings)
    for fixture in resources["fixtures"]:
        for matter in fixture["matters"]:
            for document in matter["documents"]:
                assert document["content"] not in raw_json
                assert document["content"] not in html
    assert len(resources["stores"]) == len(resources["servers"]) == 2
    assert resources["stores"][0] is not resources["stores"][1]
    assert resources["fixtures"][0] == resources["fixtures"][1]
    assert_closed(resources)


@pytest.mark.parametrize("existing", ["empty_directory", "saved_report", "file"])
def test_existing_destination_is_untouched(tmp_path, resources, existing):
    destination = tmp_path / "previous"
    if existing == "file":
        destination.write_text("keep this", encoding="utf-8")
        saved = destination
    else:
        destination.mkdir()
        saved = destination / "comparison.html"
        if existing == "saved_report":
            saved.write_text("keep this", encoding="utf-8")
    with pytest.raises(FileExistsError):
        demo.run_comparison("authorization", destination)
    assert not resources["stores"]
    if existing == "empty_directory":
        assert list(destination.iterdir()) == []
    else:
        assert saved.read_text(encoding="utf-8") == "keep this"


def test_unknown_case_creates_nothing(tmp_path, resources):
    destination = tmp_path / "unused"
    with pytest.raises(ValueError, match="Unknown case"):
        demo.run_comparison("typo", destination)
    assert not destination.exists()
    assert not resources["stores"]


def test_invalid_fixture_creates_nothing(tmp_path, resources, monkeypatch):
    fixture = tmp_path / "invalid.json"
    fixture.write_text("{}", encoding="utf-8")
    monkeypatch.setitem(demo.CASES, "authorization", fixture)
    with pytest.raises(ValueError):
        demo.run_comparison("authorization", tmp_path / "unused")
    assert not (tmp_path / "unused").exists()
    assert not resources["stores"]


def test_interruption_closes_resources(tmp_path, resources, monkeypatch, capsys):
    def interrupt(*args):
        raise KeyboardInterrupt

    monkeypatch.setattr(demo, "run_auth_scenario", interrupt)
    with pytest.raises(SystemExit) as result:
        demo.main(["--output-dir", str(tmp_path / "interrupted")])
    assert result.value.code == 130
    assert "Interrupted" in capsys.readouterr().err
    assert_closed(resources)


@pytest.mark.parametrize("failure", ["bind", "start", "evaluate", "write"])
def test_resources_close_on_failure(tmp_path, resources, monkeypatch, failure):
    def fail(*args, **kwargs):
        raise RuntimeError("injected failure")

    if failure == "start":
        original_thread = demo.Thread

        def failing_thread(*args, **kwargs):
            worker = original_thread(*args, **kwargs)
            monkeypatch.setattr(worker, "start", fail)
            return worker

        monkeypatch.setattr(demo, "Thread", failing_thread)
    else:
        monkeypatch.setattr(demo, {
            "bind": "create_server", "evaluate": "run_auth_scenario",
            "write": "write_report",
        }[failure], fail)
    with pytest.raises(RuntimeError, match="injected failure"):
        demo.run_comparison("authorization", tmp_path / "failed")
    assert resources["stores"]
    assert_closed(resources)


def test_transport_errors_save_error_findings_and_exit_two(
    tmp_path, resources, monkeypatch, capsys,
):
    def fail(*args, **kwargs):
        raise OSError("private transport detail")

    monkeypatch.setattr(demo.HttpLegalTarget, "retrieve", fail)
    output_dir = tmp_path / "errors"
    assert demo.main(["--output-dir", str(output_dir)]) == 2
    findings = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    assert [item["status"] for item in findings] == ["ERROR", "ERROR"]
    assert all(item["retrieved_document_ids"] is None for item in findings)
    assert "private transport detail" not in (output_dir / "comparison.html").read_text()
    assert "private transport detail" not in capsys.readouterr().out
    assert_closed(resources)


@pytest.mark.parametrize(
    ("statuses", "code"),
    [(["PASS", "PASS"], 0), (["FAIL", "PASS"], 1), (["FAIL", "ERROR"], 2)],
)
def test_exit_codes_use_actual_verdicts(tmp_path, monkeypatch, statuses, code):
    finding = run_auth_scenario(SecureMockTarget(), load_auth_scenario())
    findings = [finding.model_copy(update={"status": TestStatus(s)}) for s in statuses]
    monkeypatch.setattr(demo, "run_comparison", lambda *args: findings)
    assert demo.main(["--output-dir", str(tmp_path / "run")]) == code


@pytest.mark.parametrize("error", [OSError, ValueError, sqlite3.Error, RuntimeError])
def test_startup_and_output_errors_have_safe_messages(tmp_path, monkeypatch, capsys, error):
    def fail(*args):
        raise error("private error detail")

    monkeypatch.setattr(demo, "run_comparison", fail)
    with pytest.raises(SystemExit) as result:
        demo.main(["--output-dir", str(tmp_path / "run")])
    assert result.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert "Unable to finish" in output.err
    assert "private error detail" not in output.err


@pytest.mark.parametrize("case", ["authorization", "exhibit"])
def test_module_command_and_rerun_protection(tmp_path, case):
    output_dir = tmp_path / "demo output"
    command = [
        sys.executable, "-m", "examples.run_case_study", "--case", case,
        "--output-dir", str(output_dir),
    ]
    result = subprocess.run(
        command, cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert result.returncode == 1, result.stderr
    assert "SQLite vulnerable (HTTP): FAIL" in result.stdout
    assert "SQLite secure (HTTP): PASS" in result.stdout
    assert "no authentication or LLM" in result.stdout
    assert ("scripted follow-up" in result.stdout) is (case == "exhibit")
    assert str((output_dir / "comparison.html").resolve()) in result.stdout
    saved = {path.name: path.read_bytes() for path in output_dir.iterdir()}
    rerun = subprocess.run(
        command, cwd=Path(__file__).resolve().parents[1],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert rerun.returncode == 2
    assert "Choose a new output directory" in rerun.stderr
    assert {path.name: path.read_bytes() for path in output_dir.iterdir()} == saved
