"""Comando CLI para análise de Dockerfiles."""

from __future__ import annotations

import json

import typer
from rich.console import Console

from dockerls.application.use_cases.analyze_dockerfile import (
    AnalyzeDockerfileRequest,
    AnalyzeDockerfileResponse,
    AnalyzeDockerfileUseCase,
)
from dockerls.cli.dependencies import enable_console_logging
from dockerls.cli.rendering import render_validation_report
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates

console = Console()


def analyze(
    path: str = typer.Argument(".", help="Path to the Dockerfile or directory"),
    validate_only: bool = typer.Option(
        False, "--validate-only", help="Validate only, without suggesting improvements"
    ),
    suggestions: bool = typer.Option(
        True, "--suggestions/--no-suggestions", help="Show hardening suggestions"
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table or json"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Analyze a Dockerfile for security problems."""
    if verbose:
        enable_console_logging()

    validator = DockerfileValidator()
    template_provider = HardeningTemplates()
    use_case = AnalyzeDockerfileUseCase(validator, template_provider)

    request = AnalyzeDockerfileRequest(
        dockerfile_path=path,
        include_suggestions=suggestions,
        validate_only=validate_only,
    )

    response = use_case.execute(request)

    if not response.success:
        console.print(f"[red]Error:[/red] {response.error}")
        raise typer.Exit(EXIT_ERROR)

    if output_format == "json":
        # Via `typer.echo`, não pelo console do Rich: o consumidor é um
        # parser. O Rich quebra a linha na largura do terminal, e uma quebra
        # no meio de uma string do JSON produz um documento inválido -- num
        # terminal de 80 colunas era exatamente o que saía daqui.
        typer.echo(json.dumps(response.model_dump(), indent=2))
        return

    _print_table_output(response)


def _print_table_output(response: AnalyzeDockerfileResponse) -> None:
    """Imprime resultado formatado em tabela."""
    validation = response.validation
    if validation is None:
        console.print("[red]Error:[/red] validation produced no result")
        raise typer.Exit(EXIT_ERROR)

    render_validation_report(
        console,
        validation,
        analysis=response.analysis,
        suggestions=response.suggestions,
    )

    # Exit code: erro de validação é violação de política (2); warnings não
    # reprovam o build.
    if validation.errors > 0:
        raise typer.Exit(EXIT_POLICY)
    raise typer.Exit(EXIT_OK)
