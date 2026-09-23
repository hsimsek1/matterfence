from pathlib import Path

from matterfence.core.runner import run_auth_scenario
from matterfence.core.scenario import load_auth_scenario
from matterfence.report import render_report
from matterfence.targets.mock import SecureMockTarget, VulnerableMockTarget


def test_checked_in_example_report_matches_the_deterministic_run():
    """Keep the public report artifact tied to the current benchmark output."""
    report_path = Path(__file__).resolve().parents[1] / "docs" / "example-report.html"
    scenario = load_auth_scenario()
    findings = [
        run_auth_scenario(VulnerableMockTarget(), scenario),
        run_auth_scenario(SecureMockTarget(), scenario),
    ]

    assert [finding.status.value for finding in findings] == ["FAIL", "PASS"]
    assert report_path.read_text(encoding="utf-8") == render_report(findings)
