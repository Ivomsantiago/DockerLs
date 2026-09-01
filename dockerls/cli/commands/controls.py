"""`dockerls controls` -- the published controls behind each Dockerfile rule.

`analyze-dockerfile` cites a control next to every finding it reports, which
answers "why is this a problem" at the moment the reader has to act. It does
not answer the question that comes before that one: *what does this tool
check, and on whose authority*. Somebody deciding whether to put DockerLs in
front of a build has to be able to read the whole rulebook without first
producing a Dockerfile that fails.

This command is that rulebook. It also states, per rule, whether the
citation exists at all: a rule backed by CIS or NIST and a rule backed by
this project's own judgement are both legitimate, but they are not the same
claim, and collapsing them would be the same kind of overstatement as
reporting an unmeasured image as clean.
"""

from __future__ import annotations

import json

import typer
from rich.console import Console

from dockerls.cli.options import OutputFormat, parse_output_format
from dockerls.cli.text import safe
from dockerls.domain.security_controls import RULE_MAPPINGS, RuleMapping, mapping_for
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK

console = Console()

#: Shown when a rule carries no published control. Spelled out rather than
#: left blank, because a blank reads as "citation omitted".
UNDOCUMENTED_NOTE = "DockerLs guidance; no published control in the catalogue covers this rule"


def controls(
    rule: str = typer.Argument(
        "", help="Rule to explain (e.g. DF002). Omit to list the whole catalogue."
    ),
    output_format: str = typer.Option(
        OutputFormat.TABLE.value, "--format", "-f", help="Output format: table or json"
    ),
    no_color: bool = typer.Option(False, "--no-color", help="Disable colored output"),
) -> None:
    """Show the security controls each Dockerfile rule implements."""
    if no_color:
        console.no_color = True
    fmt = parse_output_format(output_format)

    if rule:
        mapping = mapping_for(rule)
        if mapping is None:
            _report_unknown(rule, fmt)
            raise typer.Exit(EXIT_ERROR)
        selected: tuple[RuleMapping, ...] = (mapping,)
    else:
        selected = RULE_MAPPINGS

    if fmt == OutputFormat.JSON:
        console.print(json.dumps([_as_dict(m) for m in selected], indent=2), soft_wrap=True)
    else:
        _render(selected, detailed=bool(rule))
    raise typer.Exit(EXIT_OK)


def _as_dict(mapping: RuleMapping) -> dict[str, object]:
    return {
        "rule_id": mapping.rule_id,
        "summary": mapping.summary,
        "rationale": mapping.rationale,
        "documented": mapping.is_documented,
        "controls": [
            {
                "source": control.source.value,
                "identifier": control.identifier,
                "title": control.title,
                "reference": str(control),
            }
            for control in mapping.controls
        ],
    }


def _report_unknown(rule: str, output_format: OutputFormat) -> None:
    known = ", ".join(mapping.rule_id for mapping in RULE_MAPPINGS)
    message = f"unknown rule: {rule}"
    if output_format == OutputFormat.JSON:
        console.print(json.dumps({"error": message, "known_rules": known.split(", ")}))
        return
    console.print(f"[red]Error:[/red] {safe(message)}")
    console.print(f"[dim]Known rules: {known}[/dim]")


def _render(mappings: tuple[RuleMapping, ...], *, detailed: bool) -> None:
    for mapping in mappings:
        console.print(f"[cyan bold]{mapping.rule_id}[/cyan bold]  {safe(mapping.summary)}")
        if detailed:
            console.print(f"  [dim]{safe(mapping.rationale)}[/dim]")
        for control in mapping.controls:
            console.print(f"  [green]->[/green] {safe(str(control))}")
        if not mapping.is_documented:
            console.print(f"  [dim]-> {UNDOCUMENTED_NOTE}[/dim]")
        console.print()

    if not detailed:
        documented = sum(1 for mapping in mappings if mapping.is_documented)
        console.print(
            f"[dim]{documented} of {len(mappings)} rules cite a published control. "
            "Run `dockerls controls DF002` to see the rationale for one rule.[/dim]"
        )
