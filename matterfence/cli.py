import json
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from matterfence.core.runner import (
    Finding,
    TestStatus,
    run_auth_scenario,
    run_mf_inject_001,
    run_mf_matter_001,
    run_mf_priv_001,
    run_mf_wall_001,
)
from matterfence.core.scenario import load_auth_scenario
from matterfence.report import write_report
from matterfence.targets.http import HttpLegalTarget
from matterfence.targets.mock import SecureMockTarget, VulnerableMockTarget

app = typer.Typer(
    name="matterfence",
    help="Adversarial security evaluation framework for legal AI.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


class TargetSelection(str, Enum):
    both = "both"
    secure = "secure"
    vulnerable = "vulnerable"
    http = "http"


def _print_finding(finding: Finding) -> None:
    """Render identifying evidence, never raw target responses or documents."""
    if finding.permitted_retrieved_document_ids is None:
        permitted = "unknown (incomplete run)"
    else:
        permitted = ", ".join(finding.permitted_retrieved_document_ids) or "none observed"
    console.print(
        f"\n{finding.scenario_id} v{finding.scenario_version} | "
        f"{finding.target_name}",
        markup=False,
    )
    console.print(
        f"User: {finding.actor.name} ({finding.actor.id})\n"
        f"Authorized matters: {', '.join(finding.authorized_matter_ids)}\n"
        f"Expected: {finding.expected_behavior}\n"
        f"Permitted retrieval: {permitted}",
        markup=False,
    )
    for resource in finding.prohibited_resources:
        retrieved = (
            "unknown"
            if resource.retrieved is None
            else str(resource.retrieved).lower()
        )
        console.print(
            f"Forbidden: {resource.matter_id} / {resource.document_title} "
            f"({resource.document_id})\n"
            f"Canary: {resource.canary_token}\n"
            f"Evidence: retrieved={retrieved}; "
            f"matter canary disclosed={str(resource.disclosed).lower()}",
            markup=False,
        )
    console.print(
        f"Observed: {finding.observed}\n"
        f"Result: {finding.status.value} | "
        f"Failure severity: {finding.severity.title()}\n"
        f"Remediation: {finding.remediation}",
        markup=False,
    )


@app.command("run")
def run(
    scenario_file: Annotated[
        Path | None,
        typer.Argument(help="Scenario JSON; defaults to bundled MF-AUTH-001."),
    ] = None,
    target: Annotated[
        TargetSelection, typer.Option(help="Mock target or local HTTP application.")
    ] = TargetSelection.both,
    endpoint: Annotated[
        str | None,
        typer.Option(help="Loopback HTTP query URL; required only for --target http."),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit a JSON array of findings.")
    ] = False,
    report: Annotated[
        Path | None,
        typer.Option("--report", help="Save offline HTML to a new file; never overwrite."),
    ] = None,
) -> None:
    """Run one observed cross-matter scenario.

    The vulnerable demo intentionally fails.
    """
    try:
        scenario = load_auth_scenario(scenario_file)
    except (OSError, ValueError):
        typer.echo(
            "Invalid scenario: provide readable UTF-8 JSON matching version 1.0.",
            err=True,
        )
        raise typer.Exit(code=2) from None

    try:
        if target == TargetSelection.http:
            if endpoint is None:
                raise ValueError("HTTP target requires an endpoint.")
            selected = [HttpLegalTarget(endpoint)]
        else:
            if endpoint is not None:
                raise ValueError("Only the HTTP target accepts an endpoint.")
            targets = {
                TargetSelection.vulnerable: VulnerableMockTarget(),
                TargetSelection.secure: SecureMockTarget(),
            }
            selected = (
                list(targets.values())
                if target == TargetSelection.both
                else [targets[target]]
            )
    except ValueError:
        typer.echo(
            "Invalid target options: use --target http with --endpoint "
            "http://127.0.0.1:PORT/path (or http://[::1]:PORT/path), "
            "without credentials, query strings, or fragments. "
            "Omit --endpoint for mock targets.",
            err=True,
        )
        raise typer.Exit(code=2) from None

    findings = [run_auth_scenario(item, scenario) for item in selected]
    if json_output:
        typer.echo(
            json.dumps(
                [item.model_dump(mode="json") for item in findings], indent=2
            )
        )
    else:
        target_kind = "HTTP target" if target == TargetSelection.http else "mock targets"
        console.print(f"MatterFence: local synthetic authorization test ({target_kind}).")
        for finding in findings:
            _print_finding(finding)

    if report is not None:
        try:
            write_report(findings, report)
        except (OSError, ValueError):
            typer.echo(
                "Unable to write HTML report. "
                "Use a new path in an existing writable folder.",
                err=True,
            )
            raise typer.Exit(code=2) from None
        typer.echo("HTML report saved.", err=True)

    exit_code = 0
    if any(item.status == TestStatus.ERROR for item in findings):
        exit_code = 2
    elif any(item.status == TestStatus.FAIL for item in findings):
        exit_code = 1
    raise typer.Exit(code=exit_code)


@app.command("scan")
def scan():
    """Run baseline security benchmark suite against local mock targets."""
    console.print(
        "\n[bold blue]MatterFence[/bold blue] - Running Legal AI Security Assessment...\n"
    )

    targets = [VulnerableMockTarget(), SecureMockTarget()]
    all_tests = [
        ("MF-MATTER-001: Cross-Matter Leakage", run_mf_matter_001),
        ("MF-WALL-001: Ethical Wall Bypass", run_mf_wall_001),
        ("MF-INJECT-001: Indirect Prompt Injection", run_mf_inject_001),
        ("MF-PRIV-001: Privileged Document Leakage", run_mf_priv_001),
    ]

    for test_name, test_fn in all_tests:
        table = Table(title=f"Assessment Results: {test_name}")
        table.add_column("Target", style="cyan")
        table.add_column("Status", style="bold")
        table.add_column("Observed Behavior", style="white")
        table.add_column("Evidence Captured", style="magenta")

        for t in targets:
            r = test_fn(t)
            status_color = "red" if r.status == TestStatus.FAIL else "green"
            table.add_row(
                r.target_name,
                f"[{status_color}]{r.status.value}[/{status_color}]",
                r.observed,
                r.evidence or "-",
            )

        console.print(table)
        console.print()


@app.command("version")
def version():
    """Display the current MatterFence version."""
    console.print("[bold]MatterFence[/bold] version: 0.2.0 (Ethical Walls)")


if __name__ == "__main__":
    app()
