"""Comando CLI para build seguro de imagens Docker."""

from __future__ import annotations

import asyncio
import json
from html import escape as html_escape
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.panel import Panel

from dockerls.application.use_cases.build_image import (
    BuildImageRequest,
    BuildImageResponse,
    BuildImageUseCase,
    BuildReport,
)
from dockerls.cli.dependencies import build_host_guard, enable_console_logging
from dockerls.cli.progress import scan_status
from dockerls.cli.publish_prompt import resolve_destination, resolve_identity
from dockerls.cli.rendering import render_validation_report
from dockerls.cli.text import safe
from dockerls.domain.value_objects.build_labels import BuildIdentity, MissingBuildMetadataError
from dockerls.domain.value_objects.build_policy import BuildPolicy
from dockerls.domain.value_objects.gate import (
    GateKind,
    GateSet,
    InvalidGateError,
    merge_gates,
)
from dockerls.domain.value_objects.inheritance import ACTIONS, FindingOrigin
from dockerls.domain.value_objects.provenance import BuildProvenance, ProvenanceStatus
from dockerls.domain.value_objects.registry_target import InvalidRegistryTargetError
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK
from dockerls.infrastructure.config.policy_file import (
    PolicyFileError,
    find_policy_file,
    load_policy,
)
from dockerls.infrastructure.dockerfile_validator import DockerfileValidator, HardeningTemplates
from dockerls.integrations.signing.cosign import (
    CosignClient,
    SignatureResult,
    SignatureStatus,
)

if TYPE_CHECKING:
    from dockerls.domain.entities.dockerfile_analysis import DockerfileValidationResult
    from dockerls.domain.value_objects.build_policy import PolicyViolation
    from dockerls.domain.value_objects.inheritance import InheritanceReport
    from dockerls.integrations.threat_intel.client import ThreatIntelClient

console = Console()


def build(
    path: str = typer.Argument(".", help="Directory containing the Dockerfile"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Image tag (required)"),
    base: str | None = typer.Option(
        None,
        "--base",
        help=(
            "Hardened base template: alpine, debian, ubuntu, distroless, "
            "node-alpine, python-alpine, maven-alpine, go-scratch, ... "
            "(--list-templates shows all 39)"
        ),
    ),
    hardened: bool = typer.Option(False, "--hardened", help="Use hardened Dockerfile templates"),
    list_templates: bool = typer.Option(
        False, "--list-templates", help="List the available hardened templates and exit"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Step-by-step security wizard"
    ),
    scan: bool = typer.Option(True, "--scan/--no-scan", help="Run Trivy/Grype after the build"),
    auto_remediate: bool = typer.Option(
        False,
        "--auto-fix",
        "--auto-remediate",
        help="Loop auto-remediation until zero vulnerabilities",
    ),
    zero_vulns: bool = typer.Option(
        False, "--zero-vulns", help="Build and remediate until zero CVEs"
    ),
    max_iterations: int = typer.Option(
        3, "--max-iterations", help="Maximum number of remediation iterations"
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Fail the build on: a severity (critical, high, medium, low), `kev` "
        "(exploited in the wild, per CISA KEV), or `epss>=N` (probability of "
        "exploitation). Combine with commas; all of them must pass",
    ),
    report: str | None = typer.Option(
        None, "--report", "-r", help="Save the security report (JSON/HTML)"
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Disable the Docker build cache"),
    build_args: str | None = typer.Option(None, "--build-args", help="Build arguments (JSON)"),
    labels: str | None = typer.Option(None, "--labels", help="Security labels (JSON)"),
    ci_mode: bool = typer.Option(
        False, "--ci-mode", help="CI/CD mode (JSON output, no interaction)"
    ),
    validate_only: bool = typer.Option(
        False, "--validate-only", help="Only validate the Dockerfile"
    ),
    suggest_hardening: bool = typer.Option(
        False, "--suggest-hardening", help="Suggest improvements without building"
    ),
    push: bool = typer.Option(False, "--push", help="docker push the tag after a successful build"),
    registry: str | None = typer.Option(
        None,
        "--registry",
        "--acr",
        help=(
            "Publish destination, without a tag: myacr.azurecr.io/apps/app, "
            "us-central1-docker.pkg.dev/proj/repo/app, gcr.io/proj/app, myorg/app"
        ),
    ),
    owner: str | None = typer.Option(
        None, "--owner", help="Owning team or person (becomes maintainer and vendor)"
    ),
    security_contact: str | None = typer.Option(
        None, "--security-contact", help="Contact for vulnerabilities in this image"
    ),
    source_url: str | None = typer.Option(
        None, "--source", help="URL of the repository that produces this image"
    ),
    provenance: str | None = typer.Option(
        None,
        "--provenance",
        help="Archive the supply-chain record (input and output hashes) as JSON",
    ),
    production: bool = typer.Option(
        False,
        "--production",
        help=(
            "Production profile: gate at critical, require a scan, pinned bases, an "
            "unprivileged user, verified provenance, ownership labels and finding "
            "attribution. Says in the output what it turned on"
        ),
    ),
    attribute: bool = typer.Option(
        False,
        "--attribute",
        help=(
            "Also scan the declared base and say whose each CVE is: the base, or the "
            "layers of this Dockerfile. Costs a second scan"
        ),
    ),
    sign: bool = typer.Option(
        False,
        "--sign",
        help=(
            "Sign the published image with cosign (keyless/OIDC). Requires --push and "
            "verified provenance"
        ),
    ),
    policy: str | None = typer.Option(
        None,
        "--policy",
        help=("Policy file to check (default: .dockerls-policy.yaml in the context, when present)"),
    ),
    no_policy: bool = typer.Option(
        False,
        "--no-policy",
        help="Ignore the context .dockerls-policy.yaml. Recorded in the output",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Ask nothing: anything missing becomes an error instead of stalling the pipeline",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose debug output"),
    output: str | None = typer.Option(None, "--output", "-o", help="Report output file"),
    force: bool = typer.Option(False, "--force", help="Build even when validation fails"),
    compare_to_analysis: str | None = typer.Option(
        None,
        "--compare-to-analysis",
        help="A report written by an earlier `analyze-dockerfile --output <file>` run "
        "on this same Dockerfile. When given, the build report says which of those "
        "findings are still present now and which were fixed",
    ),
) -> None:
    """Build secure Docker images with validation, scanning and auto-remediation."""
    if verbose:
        enable_console_logging()

    template_provider = HardeningTemplates()

    if list_templates:
        _print_templates(template_provider, ci_mode=ci_mode)
        raise typer.Exit(EXIT_OK)

    # Validar tag obrigatória (exceto em modos especiais)
    if not tag and not validate_only and not suggest_hardening and not interactive:
        console.print("[red]Error:[/red] --tag is required for build")
        raise typer.Exit(EXIT_ERROR)

    # Um limiar desconhecido não pode virar um portão que nunca reprova:
    # rejeita antes de construir qualquer coisa.
    if fail_on is not None:
        try:
            GateSet.parse(fail_on)
        except InvalidGateError as e:
            console.print(f"[red]Error:[/red] {e}")
            raise typer.Exit(EXIT_ERROR) from e

    # Uma base sem template não pode ser descoberta só depois do build ter
    # começado -- o mesmo raciocínio do `--fail-on` acima.
    if base is not None:
        known = template_provider.list_templates()
        # Nome exato. A comparação anterior perguntava se algum template era
        # *substring* do que foi digitado, então `--base alpine-inexistente`
        # passava aqui (por conter "alpine") e explodia lá dentro, na geração.
        if base.strip().lower() not in known:
            console.print(
                f"[red]Error:[/red] invalid --base: {base!r}.\n"
                f"[dim]Available: {', '.join(known)}[/dim]"
            )
            raise typer.Exit(EXIT_ERROR)

    declared_policy = _load_policy(path, policy, no_policy=no_policy)
    if production:
        declared_policy = _announce_production(declared_policy)
        attribute = True

    # Parsear JSON args
    build_args_dict = _parse_json_option(build_args, "--build-args")
    labels_dict = _parse_json_option(labels, "--labels")

    # Publicar sem veredito é a contradição que esta ferramenta existe para
    # não cometer: o portão passa a ser obrigatório para quem publica, em vez
    # de depender de alguém lembrar de passar --fail-on. `--no-scan` com push
    # é recusado de saída -- sem medição não há veredito nenhum a dar.
    publishing = push or bool(registry)
    if publishing and not scan:
        console.print(
            "[red]Error:[/red] --push with --no-scan would publish an image nobody "
            "measured. An unmeasured image is not a secure image; it is an unknown "
            "one."
        )
        raise typer.Exit(EXIT_ERROR)
    if publishing and fail_on is None:
        fail_on = "critical"
        console.print(
            "[dim]Publishing: security gate at `critical` by default "
            "(use --fail-on to change the threshold).[/dim]"
        )

    # Destino e responsabilidade são resolvidos **antes** do build: descobrir
    # que o destino está errado depois de validar, construir e escanear
    # desperdiça o trabalho inteiro, e rotular depois do build significa
    # reconstruir.
    quiet = non_interactive or ci_mode
    identity = BuildIdentity(
        owner=(owner or "").strip(),
        security_contact=(security_contact or "").strip(),
        source=(source_url or "").strip(),
        version=(tag or "").rpartition(":")[2],
        extra=labels_dict or {},
    )
    target = None
    try:
        if push or registry:
            target = resolve_destination(registry, _tag_part(tag), non_interactive=quiet)
        # Os rótulos só são exigidos de quem vai publicar: um build local para
        # experimentar não precisa de dono, e transformar isso em obstáculo
        # faria as pessoas desligarem a checagem inteira.
        if target is not None:
            identity = resolve_identity(identity, non_interactive=quiet)
    except (InvalidRegistryTargetError, MissingBuildMetadataError) as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e

    labels_dict = {**identity.to_labels(), **(labels_dict or {})}

    # Inicializar use case
    validator = DockerfileValidator(template_provider)
    # A inteligência de ameaça só é montada quando algum portão a pede:
    # `--fail-on high` não deve sair para a rede consultar KEV, e um build
    # sem portão de exploração não deve consultar nada.
    use_case = BuildImageUseCase(
        validator,
        template_provider,
        threat_intel=_threat_intel_for(fail_on, declared_policy),
        guard=build_host_guard(),
    )

    # Criar request
    request = BuildImageRequest(
        context_path=path,
        tag=tag or "temp:latest",
        dockerfile_path="Dockerfile",
        hardened=hardened,
        base_template=base,
        scan=scan,
        validate_only=validate_only,
        suggest_only=suggest_hardening,
        no_cache=no_cache,
        build_args=build_args_dict,
        labels=labels_dict,
        fail_on=fail_on,
        ci_mode=ci_mode,
        verbose=verbose,
        force=force,
        push=push or target is not None,
        push_reference=target.reference if target else "",
        provenance_path=(provenance or "").strip(),
        auto_remediate=auto_remediate or zero_vulns,
        max_remediation_rounds=max_iterations,
        target_zero_vulns=zero_vulns,
        policy=declared_policy,
        attribute_findings=attribute,
    )

    # Executar
    if interactive:
        response = _run_interactive_wizard(use_case, path)
    else:
        with scan_status(f"Building {tag or path}..."):
            response = use_case.execute(request)

    signature = _sign_if_requested(response, sign=sign, publishing=publishing)

    if compare_to_analysis and response.validation is not None:
        _print_analysis_comparison(compare_to_analysis, response.validation)

    # Output
    if ci_mode or output:
        _print_json_output(response, output, signature=signature)
    else:
        _print_table_output(response, report)
        if signature is not None:
            _print_signature(signature)

    # Assinar e falhar deixaria o pipeline verde com uma imagem publicada que
    # ninguém atestou -- e o próximo `dockerls verify` seria a primeira notícia
    # disso, tarde demais.
    if signature is not None and not signature.trustworthy:
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(response.exit_code)


def _sign_if_requested(
    response: BuildImageResponse, *, sign: bool, publishing: bool
) -> SignatureResult | None:
    """Assina a imagem publicada, quando pedido e quando é legítimo assinar.

    Duas recusas moram aqui, e as duas são sobre o mesmo erro: uma assinatura
    aponta para bytes específicos e diz "eu publiquei isto". Emiti-la sobre um
    artefato que não se sabe de onde veio transforma a assinatura em carimbo.
    """
    if not sign:
        return None
    if not publishing or not response.success:
        console.print(
            "[yellow]--sign ignored: only what was published can be signed, and this "
            "build never published.[/yellow]"
        )
        return None

    record = response.provenance
    if record is None or not record.is_verified:
        reason = record.explain() if record else "no provenance was recorded"
        console.print(
            f"[red]Signing refused:[/red] {safe(reason)}.\n"
            "[dim]Signing asserts that you published these bytes; doing it over an "
            "artifact whose inputs do not add up would be stamping the unknown.[/dim]"
        )
        return SignatureResult(
            reference=response.image_tag or "",
            status=SignatureStatus.FAILED,
            detail="provenance not verified",
        )

    digest = record.artifact.repo_digest
    reference = record.artifact.published_reference or response.image_tag or ""
    if not digest:
        console.print(
            "[red]Signing refused:[/red] the registry did not return the manifest "
            "digest.\n[dim]Signing the tag would sign what it points at now, and it "
            "can move an instant later -- the signature would stay valid over "
            "different bytes.[/dim]"
        )
        return SignatureResult(
            reference=reference,
            status=SignatureStatus.FAILED,
            detail="no manifest digest",
        )

    alvo = _digest_reference(reference, digest)
    console.print(f"[dim]Signing {safe(alvo)} with cosign (keyless).[/dim]")
    return asyncio.run(CosignClient().sign(alvo))


def _announce_production(declared: BuildPolicy | None) -> BuildPolicy:
    """Liga o perfil de produção e **diz o que ligou**.

    Um perfil que muda o comportamento em silêncio é um perfil que a pessoa
    descobre pelo build reprovando, e a primeira reação a um portão que
    reprova sem explicar é desligá-lo.

    Um `.dockerls-policy.yaml` no contexto continua valendo, e só pode
    apertar: `--production` é um piso, não um teto.
    """
    perfil = BuildPolicy.production().merged_with(declared)
    console.print("\n[bold]Production profile[/bold]")
    for regra, valor in perfil.to_dict().items():
        if valor:
            console.print(f"  [cyan]{regra}[/cyan]  [dim]{safe(_describe_rule(valor))}[/dim]")
    if declared is not None:
        console.print(
            "  [dim]combined with the context .dockerls-policy.yaml, always by the "
            "stricter side[/dim]"
        )
    console.print()
    return perfil


def _describe_rule(value: object) -> str:
    if isinstance(value, dict):
        return ", ".join(f"{k}: {v}" for k, v in value.items())
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    return str(value)


def _print_inheritance(report: InheritanceReport | None) -> None:
    """De quem é cada CVE -- a resposta para "consertar o quê?".

    Uma contagem sozinha manda consertar sem dizer o quê, e quem lê passa a
    tarde descobrindo que nada no Dockerfile dela resolve o problema.
    """
    if report is None:
        return
    if not report.available:
        console.print(
            f"\n[yellow]Attribution unavailable:[/yellow] [dim]{safe(report.explain())}[/dim]"
        )
        return

    console.print("\n[bold]Where the vulnerabilities come from[/bold]")
    console.print(f"[dim]{safe(report.explain())}[/dim]\n")

    linhas = (
        ("inherited from base", len(report.inherited), FindingOrigin.INHERITED, "yellow"),
        ("from your layers", len(report.introduced), FindingOrigin.INTRODUCED, "red"),
        ("removed in build", len(report.removed), FindingOrigin.REMOVED, "green"),
    )
    for rotulo, quantidade, origem, cor in linhas:
        if not quantidade:
            continue
        console.print(f"  [{cor}]{quantidade:>4}[/{cor}]  {rotulo}")
        console.print(f"        [dim]{safe(ACTIONS[origem])}[/dim]")

    _print_plan(report)

    if report.inherited_share >= 0.5 and report.inherited:
        console.print(
            f"\n[yellow]{report.inherited_share:.0%} of this image vulnerabilities "
            "came from the base.[/yellow]\n[dim]Changing your Dockerfile does not "
            "address that part: run `dockerls base --alternatives` to measure another "
            "base.[/dim]"
        )


def _print_analysis_comparison(baseline_path: str, validation: DockerfileValidationResult) -> None:
    """How this build's own validation compares to an earlier
    `analyze-dockerfile --output` report on the same Dockerfile.

    Both come from the exact same rule set -- `build` always runs its own
    fresh validation as step one -- so this is a same-Dockerfile,
    then-and-now comparison, not a guess about what changed.
    """
    from dockerls.cli.analysis_baseline import BaselineLoadError, compare, load_baseline_findings

    try:
        baseline = load_baseline_findings(baseline_path)
    except BaselineLoadError as e:
        console.print(f"\n[yellow]--compare-to-analysis:[/yellow] {safe(str(e))}")
        return

    result = compare(baseline, validation)
    if not result.baseline_total and not result.newly_introduced:
        return

    console.print("\n[bold]Compared to the earlier analyze-dockerfile run[/bold]")
    if result.baseline_total:
        console.print(
            f"[dim]{len(result.still_present)}/{result.baseline_total} of its "
            "warnings/errors are still present in this build.[/dim]"
        )
    for name in result.resolved:
        console.print(f"  [green]fixed[/green]     {safe(name)}")
    for name in result.still_present:
        console.print(f"  [yellow]still open[/yellow] {safe(name)}")
    for name in result.newly_introduced:
        console.print(f"  [red]new[/red]        {safe(name)}")


def _print_plan(report: InheritanceReport) -> None:
    """O plano de trabalho: origem cruzada com "existe correção?".

    Origem sozinha diz de quem é o problema; correção diz se ele tem solução.
    Só as duas juntas dizem o que fazer na segunda-feira -- e a diferença é
    grande: se nenhuma das herdadas tem correção publicada, atualizar a base é
    trabalho perdido.
    """
    plano = report.plan()
    if not plano:
        return

    console.print("\n[bold]Work plan[/bold]")
    for bucket in plano:
        de_onde = "from the base" if bucket.origin is FindingOrigin.INHERITED else "yours"
        com_correcao = "fixable" if bucket.fixable else "no fix"
        criticas = f", {bucket.critical} CRITICAL" if bucket.critical else ""
        cor = "red" if bucket.critical else "yellow"
        console.print(f"  [{cor}]{bucket.count:>4}[/{cor}]  {de_onde}, {com_correcao}{criticas}")
        console.print(f"        [dim]{safe(bucket.action())}[/dim]")
        # Os três primeiros por severidade: uma lista completa aqui viraria
        # rolagem, e quem quer todos usa --format json.
        amostra = ", ".join(f"{f.cve_id} ({f.package_name})" for f in bucket.findings[:3])
        if amostra:
            resto = f" and {bucket.count - 3} more" if bucket.count > 3 else ""
            console.print(f"        [dim]{safe(amostra)}{resto}[/dim]")


def _digest_reference(reference: str, digest: str) -> str:
    """`reg.io/app:1.0` + digest -> `reg.io/app@sha256:...`.

    A tag sai fora. `nome:tag@digest` é válido e o digest é quem manda, mas
    manter os dois convida quem lê a achar que a tag importa -- e a assinatura
    existe justamente porque ela não importa.
    """
    head = reference.split("@", 1)[0]
    repositorio, separador, cauda = head.rpartition(":")
    # `registry:5000/app` tem `:` no host, não na tag.
    if separador and "/" not in cauda:
        head = repositorio
    return f"{head}@{digest}"


def _print_signature(signature: SignatureResult) -> None:
    cor = "green" if signature.trustworthy or signature.status is SignatureStatus.SIGNED else "red"
    console.print(f"\n[{cor}]{signature.status}[/{cor}]  [dim]{safe(signature.explain())}[/dim]")
    if signature.detail and not signature.trustworthy:
        console.print(f"[dim]{safe(signature.detail)}[/dim]")


def _threat_intel_for(fail_on: str | None, policy: BuildPolicy | None) -> ThreatIntelClient | None:
    """O cliente de inteligência de ameaça, quando algum portão o exige.

    Montá-lo sempre faria todo `dockerls build` sair para a rede buscar o
    catálogo KEV e as pontuações EPSS -- para um portão que ninguém pediu.
    Montá-lo nunca faria `--fail-on kev` não ter o que consultar, e um
    portão de segurança que não avalia é a pior falha possível: a que não
    aparece.

    A pergunta é feita sobre o portão **efetivo**, política somada à linha
    de comando: um `.dockerls-policy.yaml` que exige `kev` tem de fazer o
    cliente existir mesmo que a linha de comando não peça nada.
    """
    declared = policy.fail_on if policy is not None else ""
    effective = merge_gates(declared, fail_on or "")
    if not effective:
        return None
    try:
        gates = GateSet.parse(effective)
    except InvalidGateError:
        # Valor inválido já foi recusado antes de chegar aqui; se escapou,
        # não é este o lugar de reclamar.
        return None
    if not any(gate.kind in (GateKind.KEV, GateKind.EPSS) for gate in gates.gates):
        return None

    from dockerls.integrations.threat_intel.client import ThreatIntelClient

    return ThreatIntelClient()


def _load_policy(context: str, explicit: str | None, *, no_policy: bool) -> BuildPolicy | None:
    """A política a conferir neste build, ou `None` quando não há nenhuma.

    Um arquivo de política ilegível **encerra o comando**, em vez de virar
    "sem política". A direção da falha é o que decide: uma regra que não
    carrega deixa de exigir alguma coisa, e o build passaria parecendo ter
    sido conferido. Uma chave digitada errado seria um portão aberto com cara
    de fechado, e ninguém descobre isso olhando a saída verde.
    """
    if no_policy:
        console.print(
            "[yellow]--no-policy: the context .dockerls-policy.yaml will not be "
            "conferido neste build.[/yellow]"
        )
        return None

    target = Path(explicit) if explicit else find_policy_file(Path(context))
    if target is None:
        return None
    if explicit and not target.is_file():
        console.print(f"[red]Error:[/red] policy file not found: {safe(explicit)}")
        raise typer.Exit(EXIT_ERROR)

    try:
        declared = load_policy(target)
    except PolicyFileError as e:
        console.print(f"[red]Error:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    console.print(f"[dim]Policy declared in {safe(str(target))} will be checked.[/dim]")
    return declared


def _print_policy_violations(violations: list[PolicyViolation]) -> None:
    if not violations:
        return
    console.print("\n[bold red]Policy not met[/bold red]")
    for violation in violations:
        console.print(f"  [red]x[/red] [bold]{violation.rule}[/bold]  {safe(violation.message)}")
    console.print(
        "\n[dim]These rules come from the `--production` profile and/or the context "
        ".dockerls-policy.yaml. That file is versioned alongside the code: changing it "
        "is a reviewable change, passing a different flag on the command line is "
        "not.[/dim]"
    )


def _parse_json_option(raw: str | None, flag: str) -> dict[str, str] | None:
    """Parseia um argumento JSON de linha de comando, ou aborta com exit 1."""
    if not raw:
        return None
    try:
        parsed: dict[str, str] = json.loads(raw)
    except json.JSONDecodeError as e:
        console.print(f"[red]Error parsing {flag}:[/red] {e}")
        raise typer.Exit(EXIT_ERROR) from e
    return parsed


def _print_templates(template_provider: HardeningTemplates, ci_mode: bool = False) -> None:
    """Lista os templates hardened que `--base`/`--hardened` aceitam."""
    templates = template_provider.list_templates()
    if ci_mode:
        typer.echo(json.dumps({"templates": templates}, indent=2))
        return

    console.print(Panel("[bold cyan]Available hardened templates[/bold cyan]", expand=False))

    # Agrupado por stack, com o sistema operacional visível. Uma lista plana de
    # quase quarenta nomes não responde a pergunta que a pessoa tem, que é
    # "qual serve para a MINHA aplicação, e sobre qual SO ela vai rodar".
    grouped: dict[str, list[str]] = {}
    for name in templates:
        stack = name.split("-", 1)[0] if "-" in name else name
        if name in _STANDALONE_OS:
            stack = "so"
        grouped.setdefault(stack, []).append(name)

    for stack in sorted(grouped, key=lambda s: (s != "so", s)):
        title = _STACK_TITLES.get(stack, stack.capitalize())
        console.print(f"\n[bold]{title}[/bold]")
        for name in grouped[stack]:
            console.print(f"  [cyan]{name:<18}[/cyan] [dim]{_TEMPLATE_HINTS.get(name, '')}[/dim]")

    console.print("\n[bold]Examples[/bold]")
    for example in _BUILD_EXAMPLES:
        console.print(f"  [dim]{example}[/dim]")
    console.print(
        "\n[dim]Without --base or --hardened, the build uses the Dockerfile already "
        "in the directory -- templates only apply when you ask for one.[/dim]"
    )


#: Templates que são só o sistema operacional, sem runtime de linguagem.
_STANDALONE_OS = frozenset({"alpine", "debian", "ubuntu", "distroless"})

_STACK_TITLES = {
    "so": "The operating system alone (no runtime)",
    "node": "Node.js",
    "python": "Python",
    "java": "Java (runtime)",
    "maven": "Java, built with Maven (build + runtime)",
    "gradle": "Java, built with Gradle (build + runtime)",
    "go": "Go",
    "rust": "Rust",
    "php": "PHP",
    "ruby": "Ruby",
}

#: O que distingue cada variante. Sem isto, escolher entre `node-alpine` e
#: `node-distroless` é adivinhação.
_TEMPLATE_HINTS = {
    "alpine": "musl, ~5 MB, has a shell",
    "debian": "glibc, stable, has a shell",
    "ubuntu": "glibc, more packages available",
    "distroless": "no shell and no package manager",
    "node": "Debian slim",
    "node-alpine": "musl -- watch out for native modules (sharp, bcrypt)",
    "node-debian": "glibc",
    "node-ubuntu": "glibc",
    "node-distroless": "no shell; runtime only",
    "python": "Debian slim",
    "python-alpine": "musl -- wheels must be musllinux",
    "python-debian": "glibc",
    "python-ubuntu": "glibc",
    "python-distroless": "no shell; interpreter only",
    "java": "Temurin JRE",
    "java-alpine": "Temurin JRE Alpine",
    "java-debian": "Temurin JRE Debian",
    "java-ubuntu": "Temurin JRE Ubuntu",
    "java-distroless": "no shell; JVM only",
    "maven": "builds with Maven, runs on the JRE alone",
    "maven-alpine": "builds with Maven, runs on the JRE alone Alpine",
    "gradle": "builds with Gradle, runs on the JRE alone",
    "gradle-alpine": "builds with Gradle, runs on the JRE alone Alpine",
    "go": "Debian slim",
    "go-alpine": "static musl",
    "go-debian": "glibc",
    "go-distroless": "no shell",
    "go-scratch": "the static binary alone -- the smallest surface there is",
    "rust": "Debian slim",
    "rust-alpine": "musl",
    "rust-debian": "glibc",
    "rust-scratch": "the static binary alone",
    "php": "Debian slim",
    "php-alpine": "musl",
    "php-debian": "glibc",
    "php-ubuntu": "glibc",
    "ruby": "Debian slim",
    "ruby-alpine": "musl",
    "ruby-debian": "glibc",
}

#: Exemplos reais, um por forma de uso. A pergunta que eles respondem é "como
#: eu escrevo isso", que nenhuma lista de nomes responde sozinha.
_BUILD_EXAMPLES = (
    "dockerls build -t minha-api:1.0 .",
    "     ^ uses the Dockerfile already in the directory",
    "",
    "dockerls build --hardened --base node-alpine -t minha-api:1.0 .",
    "     ^ generates a hardened Node-on-Alpine Dockerfile and builds with it",
    "",
    "dockerls build --hardened --base maven-alpine -t minha-api:1.0 --fail-on critical .",
    "     ^ Java with Maven: builds with the tool, runs on the JRE alone",
    "",
    "dockerls build --hardened --base go-scratch -t minha-api:1.0 .",
    "     ^ the static binary alone: the smallest attack surface there is",
    "",
    "dockerls build --hardened --base ubuntu -t minha-base:1.0 .",
    "     ^ the operating system only, with no language runtime",
)


def _run_interactive_wizard(use_case: BuildImageUseCase, path: str) -> BuildImageResponse:
    """Executa wizard interativo completo com questionário aprofundado."""
    console.print(
        Panel(
            "[bold cyan]DockerLs Interactive Build Wizard[/bold cyan]\n"
            "[dim]Step-by-step setup aimed at security and zero vulnerabilities[/dim]",
            expand=False,
        )
    )
    console.print()

    available = HardeningTemplates().list_templates() or [
        "node",
        "python",
        "go",
        "rust",
        "java",
        "php",
    ]

    # 1. Ecossistema / Linguagem
    console.print("[bold yellow]? 1. Which ecosystem / language is your application?[/bold yellow]")
    stacks = ["node", "python", "go", "java", "rust", "php", "other"]
    for i, s in enumerate(stacks, 1):
        console.print(f"  {i}. {s}")
    stack_choice = _prompt_choice(stacks, "1")

    # 2. Versão recomendada e particularidades
    version_options = {
        "node": ["22.x LTS (Recommended)", "20.x LTS", "18.x", "custom"],
        "python": ["3.12 (Recommended)", "3.13", "3.11", "custom"],
        "go": ["1.23 (Recommended)", "1.24", "1.22", "custom"],
        "java": ["21 LTS (Eclipse Temurin)", "17 LTS", "custom"],
        "rust": ["1.82 (Alpine musl static)", "latest", "custom"],
        "php": ["8.3 FPM/CLI", "8.2", "custom"],
    }
    opts = version_options.get(stack_choice, ["latest", "custom"])
    console.print(f"\n[bold yellow]? 2. Which version of {stack_choice} do you want?[/bold yellow]")
    for i, opt in enumerate(opts, 1):
        console.print(f"  {i}. {opt}")
    _ = _prompt_choice(opts, "1")

    # 3. Base distribution
    console.print("\n[bold yellow]? 3. Which base distribution do you prefer?[/bold yellow]")
    distros = [
        "alpine (Alpine Linux - Ultra-lightweight musl)",
        "debian (Debian Bookworm Slim - glibc)",
        "ubuntu (Ubuntu 24.04 LTS - highest package compatibility)",
        "distroless (Google Distroless - no shell, zero OS CVEs)",
        "scratch (plain scratch, for static binaries)",
    ]
    for i, d in enumerate(distros, 1):
        console.print(f"  {i}. {d}")
    distro_raw = _prompt_choice(distros, "1")
    distro_key = distro_raw.split()[0].lower()

    # 4. Usar template hardened
    console.print(
        "\n[bold yellow]? 4. Use a multi-stage template with a non-root user?[/bold yellow]"
    )
    console.print("  1. yes (recommended - reduces the attack surface)")
    console.print("  2. no (use the directory default Dockerfile)")
    use_hardened = _prompt_choice(["yes", "no"], "1") == "yes"

    # 5. Dependências do SO / build nativo
    console.print(
        "\n[bold yellow]? 5. Does your application need native OS dependencies?[/bold yellow]"
    )
    deps_opts = [
        "none (default runtime only)",
        "build-essential / gcc / make",
        "libpq (PostgreSQL client)",
        "openssl / ca-certificates",
    ]
    for i, dep in enumerate(deps_opts, 1):
        console.print(f"  {i}. {dep}")
    _ = _prompt_choice(deps_opts, "1")

    # 6. Portas
    default_port = (
        "3000"
        if stack_choice == "node"
        else "8000"
        if stack_choice in ("python", "php")
        else "8080"
    )
    port_input = (
        console.input(f"\n[bold yellow]? 6. Application port [{default_port}]: [/bold yellow]")
        or default_port
    )

    # 7. Scan pós-build
    console.print("\n[bold yellow]? 7. Run a vulnerability scan after the build?[/bold yellow]")
    scan = _prompt_choice(["yes", "no"], "1") == "yes"

    # 8. Ciclo de auto-remediação até zero vulnerabilidades
    console.print("\n[bold yellow]? 8. Loop until ZERO vulnerabilities?[/bold yellow]")
    console.print("  1. yes (patches until the CVEs are gone)")
    console.print("  2. no (only report the vulnerabilities found)")
    zero_vulns = _prompt_choice(["yes", "no"], "1") == "yes"

    # 9. Tag da imagem
    tag_input = (
        console.input("\n[bold yellow]? 9. Docker image tag [app:latest]: [/bold yellow]")
        or "app:latest"
    )

    # 10. Push para registro
    console.print("\n[bold yellow]? 10. Publish (docker push) once it passes?[/bold yellow]")
    push_choice = _prompt_choice(["no", "dockerhub", "ghcr", "harbor"], "1")

    # Determinar melhor template com base na combinação Stack + Distro
    candidate_key = f"{stack_choice}-{distro_key}"
    if candidate_key in available:
        base_template = candidate_key
    elif stack_choice in available:
        base_template = stack_choice
    elif distro_key in available:
        base_template = distro_key
    else:
        base_template = "node-alpine"

    request = BuildImageRequest(
        context_path=path,
        tag=tag_input,
        hardened=use_hardened,
        base_template=base_template if use_hardened else None,
        scan=scan,
        auto_remediate=zero_vulns,
        target_zero_vulns=zero_vulns,
        push=push_choice != "no",
        labels={"app.port": port_input, "dockerls.managed": "true"},
    )

    return use_case.execute(request)


def _prompt_choice(options: list[str], default: str = "1") -> str:
    """Solicita a escolha do usuário."""
    while True:
        try:
            choice = console.input(f"\nChoice [{default}]: ")
            if not choice:
                choice = default
            idx = int(choice) - 1
            if 0 <= idx < len(options):
                return options[idx]
        except ValueError:
            continue


def _print_table_output(response: BuildImageResponse, report_file: str | None = None) -> None:
    """Imprime resultado formatado em tabela."""
    # Nenhuma imagem construída: o resultado é a validação, e é ela que
    # precisa aparecer -- com os checks, não só com um veredito.
    if response.image_tag is None:
        _print_validation_output(response, report_file)
        return

    _print_build_output(response, report_file)


def _print_validation_output(response: BuildImageResponse, report_file: str | None) -> None:
    if response.validation is not None:
        render_validation_report(
            console,
            response.validation,
            analysis=response.analysis,
            suggestions=list(response.recommendations) or None,
            title="Dockerfile Validation",
        )

    if response.success:
        console.print(
            Panel(
                "[bold green]Validation Passed[/bold green]\n"
                "[dim]No blocking policy violations found[/dim]",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]Validation Failed[/bold red]\n\n"
                f"[red]{response.error or 'Dockerfile validation failed'}[/red]",
                expand=False,
            )
        )

    _print_policy_violations(response.policy_violations)
    _write_report_file(response.report, report_file)
    console.print()


def _print_build_output(response: BuildImageResponse, report_file: str | None) -> None:
    if not response.success:
        console.print(
            Panel(
                f"[bold red]Build Failed[/bold red]\n\n"
                f"[red]{response.error or 'Build failed'}[/red]",
                expand=False,
            )
        )
        _print_inheritance(response.inheritance)
        _print_policy_violations(response.policy_violations)
        _write_report_file(response.report, report_file)
        return

    console.print(
        Panel(
            f"[bold green]Build Successful[/bold green]\n[dim]{response.image_tag}[/dim]",
            expand=False,
        )
    )
    console.print()

    report = response.report
    if report is not None:
        _print_report(report)
        _write_report_file(report, report_file)

    _print_inheritance(response.inheritance)

    if response.provenance is not None:
        _print_provenance(response.provenance)

    if response.recommendations:
        console.print(Panel("[bold yellow]Hardening Suggestions[/bold yellow]", expand=False))
        for i, rec in enumerate(response.recommendations[:3], 1):
            console.print(f"\n{i}. [bold]{rec.title}[/bold]")
            console.print(f"   [dim]{rec.description}[/dim]")
            console.print(f"   Fix: [green]{rec.suggested_fix}[/green]")

    console.print()


def _print_report(report: BuildReport) -> None:
    tier_colors = {"A": "green", "B": "yellow", "C": "yellow", "D": "red", "F": "red"}
    tier_color = tier_colors.get(report.security_tier, "white")

    console.print(
        Panel(
            f"[bold]Security Score: {report.security_score}/100[/bold]\n"
            f"Tier: [{tier_color} bold]{report.security_tier}[/{tier_color} bold]",
            expand=False,
        )
    )
    console.print()

    validation = report.validation
    console.print(
        f"Validation: [green]{validation.get('passed', 0)} passed[/green] | "
        f"[yellow]{validation.get('warnings', 0)} warnings[/yellow] | "
        f"[red]{validation.get('errors', 0)} errors[/red]"
    )
    console.print()

    if report.scan_results:
        console.print(Panel("[bold magenta]Security Scan Results[/bold magenta]", expand=False))
        scan_data = next(iter(report.scan_results.values()))
        console.print(f"  CRITICAL: [red]{scan_data.get('critical', 0)}[/red]")
        console.print(f"  HIGH: [red]{scan_data.get('high', 0)}[/red]")
        console.print(f"  MEDIUM: [yellow]{scan_data.get('medium', 0)}[/yellow]")
        console.print(f"  LOW: [dim]{scan_data.get('low', 0)}[/dim]")
        console.print()

    if report.remediation_history:
        console.print(Panel("[bold green]Auto-Remediation Summary[/bold green]", expand=False))
        for item in report.remediation_history:
            round_num = item.get("round", 1)
            actions = item.get("actions", [])
            crit_b = item.get("critical_before", 0)
            crit_a = item.get("critical_after", 0)
            total_b = item.get("total_before", 0)
            total_a = item.get("total_after", 0)
            console.print(
                f"  [bold cyan]Round {round_num}:[/bold cyan] "
                f"Total Vulns: {total_b} -> [green]{total_a}[/green] | "
                f"Critical: {crit_b} -> [green]{crit_a}[/green]"
            )
            for action in actions:
                console.print(f"    - [dim]{action}[/dim]")
        console.print()

    if report.recommendations:
        console.print(Panel("[bold yellow]Recommendations[/bold yellow]", expand=False))
        priority_colors = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "dim"}
        for i, rec in enumerate(report.recommendations[:5], 1):
            priority = str(rec.get("priority", "MEDIUM"))
            priority_color = priority_colors.get(priority, "white")
            console.print(f"\n[{priority_color}]#{i}. {rec.get('title', '-')}[/{priority_color}]")
            console.print(f"   [dim]{rec.get('reason', '-')}[/dim]")
            console.print(f"   Fix: [green]{rec.get('suggested', '-')}[/green]")
        console.print()


def _write_report_file(report: BuildReport | None, report_file: str | None) -> None:
    if report is None or not report_file:
        return
    try:
        _save_report(report, report_file)
    except OSError as e:
        # An unwritable report destination is user error (bad path, no
        # permission), not a crash -- and it must not mask the build result
        # that was already printed above.
        console.print(f"\n[red]Could not write report to {report_file}:[/red] {e}")
        return
    console.print(f"\nReport saved: [cyan]{report_file}[/cyan]")


def _report_dict(report: BuildReport) -> dict[str, Any]:
    return {
        "build_id": report.build_id,
        "timestamp": report.timestamp,
        "image": report.image,
        "dockerfile_path": report.dockerfile_path,
        "security_score": report.security_score,
        "security_tier": report.security_tier,
        "validation": report.validation,
        "scan_results": report.scan_results,
        "recommendations": report.recommendations,
        "build_metadata": report.build_metadata,
        "remediation_history": report.remediation_history,
        "auto_remediated": report.auto_remediated,
    }


def _print_json_output(
    response: BuildImageResponse,
    output_file: str | None = None,
    *,
    signature: SignatureResult | None = None,
) -> None:
    """Imprime saída JSON (CI mode).

    Vai para stdout via `typer.echo`, não pelo console do Rich: em CI o
    consumidor é um parser, e cor ou quebra de linha por largura de terminal
    quebrariam o JSON.
    """
    output_data: dict[str, Any] = {
        "status": "SUCCESS" if response.success else "FAILED",
        "exit_code": response.exit_code,
    }

    # O relatório entra sempre que existe -- inclusive numa validação
    # reprovada, que é justamente quando o CI precisa saber o que falhou.
    if response.report is not None:
        output_data["report"] = _report_dict(response.report)
    # A procedência entra no JSON sempre que existe: é o que um portão de
    # supply chain lê para decidir, e ele não lê tabela de terminal.
    if response.provenance is not None:
        output_data["provenance"] = response.provenance.to_dict()
    if signature is not None:
        output_data["signature"] = signature.to_dict()
    if response.inheritance is not None:
        output_data["inheritance"] = response.inheritance.to_dict()
    if response.policy_violations:
        output_data["policy_violations"] = [v.to_dict() for v in response.policy_violations]
    if response.error:
        output_data["error"] = response.error

    json_output = json.dumps(output_data, indent=2)

    if output_file:
        try:
            Path(output_file).write_text(json_output, encoding="utf-8")
        except OSError as e:
            console.print(f"[red]Could not write {output_file}:[/red] {e}")
            raise typer.Exit(EXIT_ERROR) from e
        console.print(f"Report saved to {output_file}", style="dim")
    else:
        typer.echo(json_output)


def _save_report(report: BuildReport, filepath: str) -> None:
    """Salva relatório em arquivo."""
    path = Path(filepath)

    if path.suffix.lower() in (".html", ".htm"):
        path.write_text(_render_html_report(report), encoding="utf-8")
        return

    path.write_text(json.dumps(_report_dict(report), indent=2), encoding="utf-8")


def _render_html_report(report: BuildReport) -> str:
    score_color = "#22c55e" if report.security_score >= 75 else "#ef4444"
    tier_color = "#22c55e" if report.security_tier == "A" else "#ef4444"
    validation = report.validation
    # Every value below originates outside this process -- `--tag`, the
    # Dockerfile path, the tier string. Interpolated raw, a tag like
    # `x"><script>...` turned the report into an execution vector for whoever
    # opens it. The `export --format html` path already escaped; this one did
    # not, which is exactly the kind of split a security tool cannot afford.
    image = _esc(report.image)
    dockerfile_path = _esc(report.dockerfile_path)
    timestamp = _esc(report.timestamp)
    tier = _esc(report.security_tier)

    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DockerLs Build Report - {image or dockerfile_path}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {score_color}; }}
        .tier {{ font-size: 24px; color: {tier_color}; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f3f4f6; }}
        .critical {{ color: #dc2626; }}
        .high {{ color: #dc2626; }}
        .medium {{ color: #f59e0b; }}
        .low {{ color: #6b7280; }}
    </style>
</head>
<body>
    <h1>DockerLs Build Report</h1>
    <p><strong>Image:</strong> {image or "(not built)"}</p>
    <p><strong>Dockerfile:</strong> {dockerfile_path}</p>
    <p><strong>Timestamp:</strong> {timestamp}</p>

    <h2>Security Assessment</h2>
    <div class="score">{_int(report.security_score)}/100</div>
    <div class="tier">Tier: {tier}</div>

    <h2>Validation Results</h2>
    <table>
        <tr><th>Passed</th><td>{_int(validation.get("passed", 0))}</td></tr>
        <tr><th>Warnings</th><td>{_int(validation.get("warnings", 0))}</td></tr>
        <tr><th>Errors</th><td>{_int(validation.get("errors", 0))}</td></tr>
    </table>

    <h2>Vulnerability Scan</h2>
"""

    if report.scan_results:
        scan = next(iter(report.scan_results.values()))
        html += f"""
    <table>
        <tr><th>Severity</th><th>Count</th></tr>
        <tr><td class="critical">Critical</td><td>{_int(scan.get("critical", 0))}</td></tr>
        <tr><td class="high">High</td><td>{_int(scan.get("high", 0))}</td></tr>
        <tr><td class="medium">Medium</td><td>{_int(scan.get("medium", 0))}</td></tr>
        <tr><td class="low">Low</td><td>{_int(scan.get("low", 0))}</td></tr>
    </table>
"""
    else:
        html += "    <p>No scan was run.</p>\n"

    if report.remediation_history:
        html += """
    <h2>Auto-Remediation Summary</h2>
    <table>
        <tr>
            <th>Round</th>
            <th>Fixes Applied</th>
            <th>Critical (Before &rarr; After)</th>
            <th>Total (Before &rarr; After)</th>
        </tr>
"""
        for item in report.remediation_history:
            round_num = _int(item.get("round", 1))
            actions_str = _esc("<br>".join(item.get("actions", [])))
            cb = _int(item.get("critical_before", 0))
            ca = _int(item.get("critical_after", 0))
            tb = _int(item.get("total_before", 0))
            ta = _int(item.get("total_after", 0))
            html += (
                f"        <tr><td>{round_num}</td><td>{actions_str}</td>"
                f"<td>{cb} &rarr; {ca}</td><td>{tb} &rarr; {ta}</td></tr>\n"
            )
        html += "    </table>\n"

    return (
        html
        + """
</body>
</html>"""
    )


def _esc(value: object) -> str:
    """HTML-escape a report value, quotes included, for attribute safety."""
    return html_escape(str(value), quote=True)


def _int(value: object) -> int:
    """Counts come from scanner JSON, so they are numbers by convention, not
    by guarantee. Coercing keeps a non-numeric value from reaching the page
    as markup."""
    if isinstance(value, bool) or not isinstance(value, int | float | str):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _tag_part(tag: str | None) -> str:
    """A tag de `nome:tag`, ou `latest` quando não há uma.

    O destino recebe host e caminho; a tag vem daqui, de um lugar só, para
    não haver duas fontes discordando sobre qual versão está sendo publicada.
    """
    value = (tag or "").strip()
    if ":" in value:
        return value.rpartition(":")[2] or "latest"
    return "latest"


def _print_provenance(provenance: BuildProvenance) -> None:
    """Os hashes de antes e depois, e o que a comparação entre eles diz.

    Impresso mesmo quando tudo bate: o valor de uma cadeia de fornecimento
    está em ser vista rotineiramente, não só quando quebra -- quem nunca leu
    o registro íntegro não reconhece o rompido.
    """
    status = provenance.status
    colors = {
        ProvenanceStatus.VERIFIED: "green",
        ProvenanceStatus.INCOMPLETE: "yellow",
        ProvenanceStatus.INPUT_CHANGED: "red",
    }
    color = colors.get(status, "white")
    console.print(Panel(f"[bold {color}]Supply chain: {status}[/bold {color}]", expand=False))
    console.print(f"  [dim]{safe(provenance.explain())}[/dim]\n")

    source = provenance.source
    console.print("[bold]INPUT[/bold] [dim](measured before the build)[/dim]")
    console.print(f"  Dockerfile  {safe(source.dockerfile) or '[dim]not digested[/dim]'}")
    console.print(
        f"  Contexto    {safe(source.context) or '[dim]not digested[/dim]'}"
        f"  [dim]({source.context_files} files)[/dim]"
    )
    if source.git_revision:
        dirty = " [yellow](dirty tree)[/yellow]" if source.git_dirty else ""
        console.print(f"  Commit      {safe(source.git_revision)}{dirty}")
    for reference, digest in source.base_images.items():
        pinned = safe(digest) if digest else "[yellow]moving tag, no digest[/yellow]"
        console.print(f"  Base        {safe(reference)} -> {pinned}")

    artifact = provenance.artifact
    console.print("\n[bold]OUTPUT[/bold] [dim](measured after the build)[/dim]")
    console.print(f"  Image       {safe(artifact.image_id) or '[dim]unknown[/dim]'}")
    if artifact.repo_digest:
        console.print(f"  Manifesto   {safe(artifact.repo_digest)}")
    if artifact.published_reference:
        console.print(f"  Publicada   {safe(artifact.published_reference)}")
    console.print()
