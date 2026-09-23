import json
import os
import subprocess
import sysconfig
from importlib.metadata import version
from pathlib import Path

import pytest


def test_installed_command_reports_installed_version(tmp_path):
    command_name = "matterfence.exe" if os.name == "nt" else "matterfence"
    command = Path(sysconfig.get_path("scripts")) / command_name
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)

    result = subprocess.run(
        [str(command), "version"],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == f"MatterFence version: {version('matterfence')}\n"
    assert result.stderr == ""


@pytest.mark.parametrize(
    ("selection", "statuses", "exit_code"),
    [
        (["--target", "secure"], ["PASS"], 0),
        (["--target", "vulnerable"], ["FAIL"], 1),
        ([], ["FAIL", "PASS"], 1),
    ],
)
def test_installed_command_loads_bundled_scenario(
    tmp_path, selection, statuses, exit_code
):
    # Use the command belonging to this interpreter's installation, not PATH.
    command_name = "matterfence.exe" if os.name == "nt" else "matterfence"
    command = Path(sysconfig.get_path("scripts")) / command_name
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    report = tmp_path / "installed evidence report.html"

    # No MatterFence imports: the installed command must find its own code/data.
    result = subprocess.run(
        [str(command), "run", "--json", "--report", str(report), *selection],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,  # The vulnerable mock intentionally exits with status 1.
    )

    assert result.returncode == exit_code, result.stdout + result.stderr
    assert result.stderr.strip() == "HTML report saved."
    html = report.read_text(encoding="utf-8")
    assert "<html" in html
    assert "MatterFence" in html
    findings = json.loads(result.stdout)
    assert [finding["status"] for finding in findings] == statuses
    for finding in findings:
        assert finding["target_name"] in html
        assert finding["status"] in html
        assert finding["scenario_id"] == "MF-AUTH-001"
        assert finding["actor"]["id"] == "USR_BOB"
        assert finding["authorized_matter_ids"] == ["M101"]
        expected_ids = ["DOC_M101_TIMELINE"]
        if finding["status"] == "FAIL":
            expected_ids.append("DOC_M105_STRATEGY")
        assert finding["retrieved_document_ids"] == expected_ids
        assert finding["permitted_retrieved_document_ids"] == ["DOC_M101_TIMELINE"]
        evidence = finding["prohibited_resources"][0]
        assert evidence["document_id"] == "DOC_M105_STRATEGY"
        assert evidence["canary_token"] == "MF_CANARY_M105_PRIVILEGED_7C91"
        assert evidence["retrieved"] == (finding["status"] == "FAIL")
        assert evidence["disclosed"] == (finding["status"] == "FAIL")
