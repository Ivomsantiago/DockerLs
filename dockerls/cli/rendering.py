"""Shared Rich rendering for Dockerfile validation results.

`analyze-dockerfile` and `build --validate-only` report the same thing --
which OWASP checks a Dockerfile passed, warned on or failed -- so they render
it through the same code. Duplicating the table is how the two commands
started drifting apart, with `build` printing nothing at all.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.table import Table

from dockerls.domain.entities.dockerfile_analysis import ValidationStatus

if TYPE_CHECKING:
    from rich.console import Console

    from dockerls.domain.entities.dockerfile_analysis import (
        DockerfileAnalysis,
        DockerfileValidationResult,
        HardeningRule,
    )

# Valores de status renderizados, não senhas.
_STATUS_ICONS = {  # nosec B105
    "PASS": "[green]PASS[/green]",  # nosec B105
    "WARN": "[yellow]WARN[/yellow]",
    "FAIL": "[red]FAIL[/red]",
    "SKIP": "[dim]SKIP[/dim]",
}

_SEVERITY_STYLES = {
    "CRITICAL": "red bold",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "dim",
    "INFO": "dim",
}

_TIER_COLORS = {"A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}


def render_validation_report(
    console: Console,
    validation: DockerfileValidationResult,
    analysis: DockerfileAnalysis | None = None,
    suggestions: list[HardeningRule] | None = None,
    title: str = "Dockerfile Analysis Report",
) -> None:
    """Render the header, summary, checks table, score and suggestions.

    Every section is optional except the checks table: a caller that has no
    analysis or no suggestions simply gets fewer panels, never a `None`.
    """
    _render_header(console, validation, title)
    _render_summary(console, validation)
    _render_checks(console, validation)
    if analysis is not None:
        _render_score(console, analysis)
    if suggestions:
        _render_suggestions(console, suggestions)


def _render_header(console: Console, validation: DockerfileValidationResult, title: str) -> None:
    path = validation.dockerfile_path or "Dockerfile"
    console.print(Panel(f"[bold cyan]{title}[/bold cyan]\n[dim]{path}[/dim]", expand=False))
    console.print()


def _render_summary(console: Console, validation: DockerfileValidationResult) -> None:
    status_color = "green" if validation.errors == 0 else "red"
    console.print(
        f"[{status_color} bold]Summary:[/{status_color} bold] "
        f"[green]{validation.passed} passed[/green] | "
        f"[yellow]{validation.warnings} warnings[/yellow] | "
        f"[red]{validation.errors} errors[/red]"
    )
    console.print()


def _render_checks(console: Console, validation: DockerfileValidationResult) -> None:
    if not validation.checks:
        console.print("[dim]No validation checks were produced for this Dockerfile.[/dim]")
        console.print()
        return

    table = Table(title="Validation Checks", expand=False)
    table.add_column("Status", style="bold", width=8)
    table.add_column("Check", style="cyan")
    table.add_column("Message", style="white")
    table.add_column("Severity", justify="center")

    for check in validation.checks:
        severity = check.severity.value
        severity_style = _SEVERITY_STYLES.get(severity, "")
        table.add_row(
            _STATUS_ICONS.get(check.status.value, check.status.value),
            check.check,
            check.message,
            f"[{severity_style}]{severity}[/{severity_style}]" if severity_style else severity,
        )

    console.print(table)
    console.print()
    _render_controls(console, validation)


def _render_controls(console: Console, validation: DockerfileValidationResult) -> None:
    """Cite the published control behind each finding that failed.

    Only failures and warnings: a passing check needs no justification, and
    printing a citation for all twelve rules would bury the two the reader
    has to act on.

    A rule with no published control says so. Leaving the line out would
    read as "citation omitted", and the difference between "this is CIS 4.1"
    and "this is our opinion" is exactly what the reader is entitled to.
    """
    actionable = [
        check
        for check in validation.checks
        if check.status in (ValidationStatus.FAIL, ValidationStatus.WARN) and check.rule_id
    ]
    if not actionable:
        return

    console.print("[bold]Reference controls[/bold]")
    seen: set[str] = set()
    for check in actionable:
        rule_id = check.rule_id or ""
        if rule_id in seen:
            continue
        seen.add(rule_id)
        console.print(f"  [cyan]{rule_id}[/cyan]  {check.check}")
        if check.rationale:
            console.print(f"    [dim]{check.rationale}[/dim]")
        for reference in check.references:
            console.print(f"    [green]->[/green] {reference}")
        if not check.references:
            console.print(
                "    [dim]-> DockerLs guidance; no published control in the catalogue "
                "covers this rule[/dim]"
            )
    console.print()


def _render_score(console: Console, analysis: DockerfileAnalysis) -> None:
    tier_color = _TIER_COLORS.get(analysis.security_tier, "white")
    ready = "[green]Yes[/green]" if analysis.is_production_ready else "[red]No[/red]"
    console.print(
        Panel(
            f"[bold]Security Score: {analysis.security_score}/100[/bold]\n"
            f"Tier: [{tier_color} bold]{analysis.security_tier}[/{tier_color} bold]\n"
            f"Production Ready: {ready}",
            expand=False,
        )
    )
    console.print()


def _render_suggestions(console: Console, suggestions: list[HardeningRule]) -> None:
    console.print(Panel("[bold yellow]Recommendations[/bold yellow]", expand=False))

    for i, suggestion in enumerate(suggestions, 1):
        priority_style = _SEVERITY_STYLES.get(suggestion.priority.value, "")
        console.print(f"\n[{priority_style}]#{i}. {suggestion.title}[/{priority_style}]")
        console.print(f"   [dim]{suggestion.description}[/dim]")
        console.print(f"   Current: [yellow]{suggestion.current_state}[/yellow]")
        console.print(f"   Fix: [green]{suggestion.suggested_fix}[/green]")
        console.print(f"   [italic]Reason: {suggestion.reason}[/italic]")

    console.print()
