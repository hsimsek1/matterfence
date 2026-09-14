import typer
from rich.console import Console
from rich.table import Table

from matterfence.core.runner import (
    TestStatus,
    run_mf_inject_001,
    run_mf_matter_001,
    run_mf_wall_001,
)
from matterfence.targets.mock import SecureMockTarget, VulnerableMockTarget

app = typer.Typer(
    name="matterfence",
    help="Adversarial security evaluation framework for legal AI.",
    no_args_is_help=True,
    add_completion=False,
)

console = Console()


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
