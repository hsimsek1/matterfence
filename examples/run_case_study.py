"""Run a synthetic SQLite comparison and save evidence from a source checkout."""

import argparse
import json
import sqlite3
import sys
from contextlib import closing
from pathlib import Path
from threading import Thread

from examples.retrieval_case_study import (
    EXHIBIT_FIXTURE,
    FIXTURE,
    build_store,
    create_server,
)
from matterfence.core.runner import Finding, TestStatus, run_auth_scenario
from matterfence.core.scenario import CrossMatterScenario, load_auth_scenario
from matterfence.report import write_report
from matterfence.targets.http import HttpLegalTarget

CASES = {
    "authorization": FIXTURE,
    "exhibit": EXHIBIT_FIXTURE,
    "wall": Path(__file__).with_name("ethical_wall.json"),
}


def _run_mode(
    scenario: CrossMatterScenario, mode: str, *, review: bool,
) -> Finding:
    """Evaluate one fresh SQLite store over HTTP; close it before returning."""
    with (
        closing(build_store(scenario.model_dump())) as store,
        create_server(store, mode, review=review) as server,
    ):
        thread = Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True,
        )
        thread.start()
        try:
            target = HttpLegalTarget(f"http://127.0.0.1:{server.server_port}/retrieve")
            finding = run_auth_scenario(target, scenario)
        finally:
            # Stop request handling before closing its socket and database.
            server.shutdown()
            thread.join()
    # Label the controlled server mode, without changing verdict or evidence.
    return finding.model_copy(update={"target_name": f"SQLite {mode} (HTTP)"})


def run_comparison(case: str, output_dir: Path) -> list[Finding]:
    """Run both modes and save JSON/HTML in a new folder; return their findings."""
    if case not in CASES:
        raise ValueError("Unknown case study.")
    scenario = load_auth_scenario(CASES[case])
    # Refuse even an empty existing folder before starting either server.
    output_dir.mkdir(parents=True, exist_ok=False)
    findings = [
        _run_mode(scenario, mode, review=case == "exhibit")
        for mode in ("vulnerable", "secure")
    ]
    with (output_dir / "findings.json").open("x", encoding="utf-8") as output:
        json.dump([item.model_dump(mode="json") for item in findings], output, indent=2)
        output.write("\n")
    write_report(findings, output_dir / "comparison.html")
    return findings


def main(argv: list[str] | None = None) -> int:
    """Read arguments, save a comparison, and return the existing verdict exit code."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=tuple(CASES), default="authorization")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        findings = run_comparison(args.case, args.output_dir)
    except FileExistsError:
        parser.exit(2, "Output path already exists. Choose a new output directory.\n")
    except (OSError, ValueError, sqlite3.Error, RuntimeError):
        parser.exit(
            2, "Unable to finish: check the output location, bundled fixtures, and "
            "SQLite FTS5. Any partial output was left in place; use a new folder.\n",
        )
    except KeyboardInterrupt:
        parser.exit(130, "Interrupted. Any partial output was left in place.\n")
    print("Synthetic SQLite comparison: real local HTTP; no authentication or LLM.")
    if args.case == "exhibit":
        print("Exhibit review uses one scripted follow-up search, not a real model.")
    for finding in findings:
        print(f"{finding.target_name}: {finding.status.value}")
    print(f"Report: {(args.output_dir / 'comparison.html').resolve()}")
    print(f"Findings: {(args.output_dir / 'findings.json').resolve()}")
    print("The vulnerable case is intentionally unsafe; a FAIL gives exit code 1.")
    if any(item.status == TestStatus.ERROR for item in findings):
        return 2
    return 1 if any(item.status == TestStatus.FAIL for item in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
