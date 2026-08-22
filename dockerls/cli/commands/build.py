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
from dockerls.cli.dependencies import enable_console_logging
from dockerls.cli.publish_prompt import resolve_destination, resolve_identity
from dockerls.cli.rendering import render_validation_report
from dockerls.cli.text import safe
from dockerls.domain.value_objects.build_labels import BuildIdentity, MissingBuildMetadataError
from dockerls.domain.value_objects.build_policy import BuildPolicy
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
    from dockerls.domain.value_objects.build_policy import PolicyViolation
    from dockerls.domain.value_objects.inheritance import InheritanceReport

console = Console()


def build(
    path: str = typer.Argument(".", help="Diretório com Dockerfile"),
    tag: str | None = typer.Option(None, "--tag", "-t", help="Tag da imagem (obrigatório)"),
    base: str | None = typer.Option(
        None,
        "--base",
        help=(
            "Template hardened da base: alpine, debian, ubuntu, distroless, "
            "node-alpine, python-alpine, maven-alpine, go-scratch, ... "
            "(--list-templates mostra os 39)"
        ),
    ),
    hardened: bool = typer.Option(False, "--hardened", help="Usa templates Dockerfile hardened"),
    list_templates: bool = typer.Option(
        False, "--list-templates", help="Lista os templates hardened disponíveis e sai"
    ),
    interactive: bool = typer.Option(
        False, "--interactive", "-i", help="Wizard de segurança passo a passo"
    ),
    scan: bool = typer.Option(True, "--scan/--no-scan", help="Executa Trivy/Grype após build"),
    auto_remediate: bool = typer.Option(
        False,
        "--auto-fix",
        "--auto-remediate",
        help="Executa ciclo de auto-remediação até zero vulnerabilidades",
    ),
    zero_vulns: bool = typer.Option(
        False, "--zero-vulns", help="Garante build e remediação até zero CVEs"
    ),
    max_iterations: int = typer.Option(
        3, "--max-iterations", help="Número máximo de iterações de remediação"
    ),
    fail_on: str | None = typer.Option(
        None, "--fail-on", help="Reprova build se tiver critical/high"
    ),
    report: str | None = typer.Option(
        None, "--report", "-r", help="Salva relatório de segurança (JSON/HTML)"
    ),
    no_cache: bool = typer.Option(False, "--no-cache", help="Desativa cache do Docker"),
    build_args: str | None = typer.Option(None, "--build-args", help="Argumentos de build (JSON)"),
    labels: str | None = typer.Option(None, "--labels", help="Labels de segurança (JSON)"),
    ci_mode: bool = typer.Option(
        False, "--ci-mode", help="Modo CI/CD (output JSON, sem interação)"
    ),
    validate_only: bool = typer.Option(False, "--validate-only", help="Apenas valida Dockerfile"),
    suggest_hardening: bool = typer.Option(
        False, "--suggest-hardening", help="Sugere melhorias sem build"
    ),
    push: bool = typer.Option(
        False, "--push", help="Faz docker push da tag após um build bem-sucedido"
    ),
    registry: str | None = typer.Option(
        None,
        "--registry",
        "--acr",
        help=(
            "Destino da publicação, sem tag: meuacr.azurecr.io/apps/app, "
            "us-central1-docker.pkg.dev/proj/repo/app, gcr.io/proj/app, minhaorg/app"
        ),
    ),
    owner: str | None = typer.Option(
        None, "--owner", help="Time ou pessoa responsável (vira maintainer e vendor)"
    ),
    security_contact: str | None = typer.Option(
        None, "--security-contact", help="Contato para vulnerabilidades nesta imagem"
    ),
    source_url: str | None = typer.Option(
        None, "--source", help="URL do repositório que gera a imagem"
    ),
    provenance: str | None = typer.Option(
        None,
        "--provenance",
        help="Arquiva o registro de supply chain (hashes de entrada e saída) em JSON",
    ),
    production: bool = typer.Option(
        False,
        "--production",
        help=(
            "Perfil de produção: liga o portão em critical, exige scan, bases fixadas, "
            "usuário sem privilégio, procedência verificada, rótulos de "
            "responsabilidade e atribuição dos achados. Diz na saída o que ligou"
        ),
    ),
    attribute: bool = typer.Option(
        False,
        "--attribute",
        help=(
            "Escaneia também a base declarada e diz de quem é cada CVE: dela ou das "
            "camadas deste Dockerfile. Custa um segundo scan"
        ),
    ),
    sign: bool = typer.Option(
        False,
        "--sign",
        help=(
            "Assina a imagem publicada com cosign (keyless/OIDC). Exige --push e "
            "procedência verificada"
        ),
    ),
    policy: str | None = typer.Option(
        None,
        "--policy",
        help=(
            "Arquivo de política a conferir (padrão: .dockerls-policy.yaml no "
            "contexto, quando existir)"
        ),
    ),
    no_policy: bool = typer.Option(
        False,
        "--no-policy",
        help="Ignora o .dockerls-policy.yaml do contexto. Fica registrado na saída",
    ),
    non_interactive: bool = typer.Option(
        False,
        "--non-interactive",
        help="Não pergunta nada: o que faltar vira erro, em vez de travar o pipeline",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Debug detalhado"),
    output: str | None = typer.Option(None, "--output", "-o", help="Arquivo de saída do relatório"),
    force: bool = typer.Option(False, "--force", help="Força build mesmo com erros de validação"),
) -> None:
    """Constrói imagens Docker seguras com validação, scanning e auto-remediação."""
    if verbose:
        enable_console_logging()

    template_provider = HardeningTemplates()

    if list_templates:
        _print_templates(template_provider, ci_mode=ci_mode)
        raise typer.Exit(EXIT_OK)

    # Validar tag obrigatória (exceto em modos especiais)
    if not tag and not validate_only and not suggest_hardening and not interactive:
        console.print("[red]Error:[/red] --tag é obrigatório para build")
        raise typer.Exit(EXIT_ERROR)

    # Um limiar desconhecido não pode virar um portão que nunca reprova:
    # rejeita antes de construir qualquer coisa.
    if fail_on is not None and fail_on.strip().lower() not in BuildImageUseCase.FAIL_ON_THRESHOLDS:
        valid = ", ".join(BuildImageUseCase.FAIL_ON_THRESHOLDS)
        console.print(f"[red]Error:[/red] --fail-on inválido: {fail_on!r}. Use um de: {valid}")
        raise typer.Exit(EXIT_ERROR)

    # Uma base sem template não pode ser descoberta só depois do build ter
    # começado -- o mesmo raciocínio do `--fail-on` acima.
    if base is not None:
        known = template_provider.list_templates()
        # Nome exato. A comparação anterior perguntava se algum template era
        # *substring* do que foi digitado, então `--base alpine-inexistente`
        # passava aqui (por conter "alpine") e explodia lá dentro, na geração.
        if base.strip().lower() not in known:
            console.print(
                f"[red]Error:[/red] --base inválido: {base!r}.\n"
                f"[dim]Disponíveis: {', '.join(known)}[/dim]"
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
            "[red]Error:[/red] --push com --no-scan publicaria uma imagem que ninguém "
            "mediu. Uma imagem não medida não é uma imagem segura; é uma imagem "
            "desconhecida."
        )
        raise typer.Exit(EXIT_ERROR)
    if publishing and fail_on is None:
        fail_on = "critical"
        console.print(
            "[dim]Publicando: portão de segurança em `critical` por padrão "
            "(use --fail-on para mudar o limiar).[/dim]"
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
    validator = DockerfileValidator()
    use_case = BuildImageUseCase(validator, template_provider)

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
    response = _run_interactive_wizard(use_case, path) if interactive else use_case.execute(request)

    signature = _sign_if_requested(response, sign=sign, publishing=publishing)

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
            "[yellow]--sign ignorado: só se assina o que foi publicado, e este build "
            "não chegou a publicar.[/yellow]"
        )
        return None

    record = response.provenance
    if record is None or not record.is_verified:
        motivo = record.explain() if record else "não houve registro de procedência"
        console.print(
            f"[red]Assinatura recusada:[/red] {safe(motivo)}.\n"
            "[dim]Assinar é afirmar que você publicou estes bytes; fazê-lo sobre um "
            "artefato cuja entrada não fecha seria carimbar o desconhecido.[/dim]"
        )
        return SignatureResult(
            reference=response.image_tag or "",
            status=SignatureStatus.FAILED,
            detail="procedência não verificada",
        )

    digest = record.artifact.repo_digest
    reference = record.artifact.published_reference or response.image_tag or ""
    if not digest:
        console.print(
            "[red]Assinatura recusada:[/red] o registry não devolveu o digest do "
            "manifesto.\n[dim]Assinar a tag assinaria o que ela aponta agora, e ela "
            "pode mover no instante seguinte -- a assinatura seguiria válida cobrindo "
            "outros bytes.[/dim]"
        )
        return SignatureResult(
            reference=reference,
            status=SignatureStatus.FAILED,
            detail="sem digest do manifesto",
        )

    alvo = _digest_reference(reference, digest)
    console.print(f"[dim]Assinando {safe(alvo)} com cosign (keyless).[/dim]")
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
    console.print("\n[bold]Perfil de produção[/bold]")
    for regra, valor in perfil.to_dict().items():
        if valor:
            console.print(f"  [cyan]{regra}[/cyan]  [dim]{safe(_describe_rule(valor))}[/dim]")
    if declared is not None:
        console.print(
            "  [dim]somado ao .dockerls-policy.yaml do contexto, sempre pelo lado "
            "mais estrito[/dim]"
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
            f"\n[yellow]Atribuição indisponível:[/yellow] [dim]{safe(report.explain())}[/dim]"
        )
        return

    console.print("\n[bold]De onde vêm as vulnerabilidades[/bold]")
    console.print(f"[dim]{safe(report.explain())}[/dim]\n")

    linhas = (
        ("herdadas da base", len(report.inherited), FindingOrigin.INHERITED, "yellow"),
        ("das suas camadas", len(report.introduced), FindingOrigin.INTRODUCED, "red"),
        ("removidas no build", len(report.removed), FindingOrigin.REMOVED, "green"),
    )
    for rotulo, quantidade, origem, cor in linhas:
        if not quantidade:
            continue
        console.print(f"  [{cor}]{quantidade:>4}[/{cor}]  {rotulo}")
        console.print(f"        [dim]{safe(ACTIONS[origem])}[/dim]")

    if report.inherited_share >= 0.5 and report.inherited:
        console.print(
            f"\n[yellow]{report.inherited_share:.0%} das vulnerabilidades desta imagem "
            "vieram da base.[/yellow]\n[dim]Mexer no seu Dockerfile não resolve essa "
            "parte: rode `dockerls base --alternatives` para medir outra base.[/dim]"
        )


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
            "[yellow]--no-policy: o .dockerls-policy.yaml do contexto não será "
            "conferido neste build.[/yellow]"
        )
        return None

    target = Path(explicit) if explicit else find_policy_file(Path(context))
    if target is None:
        return None
    if explicit and not target.is_file():
        console.print(f"[red]Error:[/red] arquivo de política não encontrado: {safe(explicit)}")
        raise typer.Exit(EXIT_ERROR)

    try:
        declared = load_policy(target)
    except PolicyFileError as e:
        console.print(f"[red]Error:[/red] {safe(str(e))}")
        raise typer.Exit(EXIT_ERROR) from e

    console.print(f"[dim]Política declarada em {safe(str(target))} será conferida.[/dim]")
    return declared


def _print_policy_violations(violations: list[PolicyViolation]) -> None:
    if not violations:
        return
    console.print("\n[bold red]Política não cumprida[/bold red]")
    for violation in violations:
        console.print(f"  [red]x[/red] [bold]{violation.rule}[/bold]  {safe(violation.message)}")
    console.print(
        "\n[dim]Estas regras vêm do perfil `--production` e/ou do "
        ".dockerls-policy.yaml do contexto. O arquivo é versionado junto do código: "
        "mudá-lo é uma alteração revisável, passar uma flag diferente na linha de "
        "comando não é.[/dim]"
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

    console.print(Panel("[bold cyan]Templates hardened disponíveis[/bold cyan]", expand=False))

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

    console.print("\n[bold]Exemplos[/bold]")
    for example in _BUILD_EXAMPLES:
        console.print(f"  [dim]{example}[/dim]")
    console.print(
        "\n[dim]Sem --base nem --hardened, o build usa o Dockerfile que já está no "
        "diretório -- os templates só entram quando você pede um.[/dim]"
    )


#: Templates que são só o sistema operacional, sem runtime de linguagem.
_STANDALONE_OS = frozenset({"alpine", "debian", "ubuntu", "distroless"})

_STACK_TITLES = {
    "so": "Sistema operacional puro (sem runtime)",
    "node": "Node.js",
    "python": "Python",
    "java": "Java (runtime)",
    "maven": "Java com Maven (build + runtime)",
    "gradle": "Java com Gradle (build + runtime)",
    "go": "Go",
    "rust": "Rust",
    "php": "PHP",
    "ruby": "Ruby",
}

#: O que distingue cada variante. Sem isto, escolher entre `node-alpine` e
#: `node-distroless` é adivinhação.
_TEMPLATE_HINTS = {
    "alpine": "musl, ~5 MB, com shell",
    "debian": "glibc, estável, com shell",
    "ubuntu": "glibc, mais pacotes disponíveis",
    "distroless": "sem shell nem gerenciador de pacotes",
    "node": "Debian slim",
    "node-alpine": "musl -- atenção a módulos nativos (sharp, bcrypt)",
    "node-debian": "glibc",
    "node-ubuntu": "glibc",
    "node-distroless": "sem shell; só o runtime",
    "python": "Debian slim",
    "python-alpine": "musl -- wheels precisam ser musllinux",
    "python-debian": "glibc",
    "python-ubuntu": "glibc",
    "python-distroless": "sem shell; só o interpretador",
    "java": "Temurin JRE",
    "java-alpine": "Temurin JRE Alpine",
    "java-debian": "Temurin JRE Debian",
    "java-ubuntu": "Temurin JRE Ubuntu",
    "java-distroless": "sem shell; só a JVM",
    "maven": "constrói com Maven, roda só com JRE",
    "maven-alpine": "constrói com Maven, roda só com JRE Alpine",
    "gradle": "constrói com Gradle, roda só com JRE",
    "gradle-alpine": "constrói com Gradle, roda só com JRE Alpine",
    "go": "Debian slim",
    "go-alpine": "musl estático",
    "go-debian": "glibc",
    "go-distroless": "sem shell",
    "go-scratch": "binário estático sozinho -- a menor superfície possível",
    "rust": "Debian slim",
    "rust-alpine": "musl",
    "rust-debian": "glibc",
    "rust-scratch": "binário estático sozinho",
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
    "     ^ usa o Dockerfile que já existe no diretório",
    "",
    "dockerls build --hardened --base node-alpine -t minha-api:1.0 .",
    "     ^ gera um Dockerfile hardened de Node sobre Alpine e constrói com ele",
    "",
    "dockerls build --hardened --base maven-alpine -t minha-api:1.0 --fail-on critical .",
    "     ^ Java com Maven: constrói com a ferramenta, roda só com o JRE",
    "",
    "dockerls build --hardened --base go-scratch -t minha-api:1.0 .",
    "     ^ binário estático sozinho: a menor superfície de ataque possível",
    "",
    "dockerls build --hardened --base ubuntu -t minha-base:1.0 .",
    "     ^ só o sistema operacional, sem runtime de linguagem",
)


def _run_interactive_wizard(use_case: BuildImageUseCase, path: str) -> BuildImageResponse:
    """Executa wizard interativo completo com questionário aprofundado."""
    console.print(
        Panel(
            "[bold cyan]🐳 DockerLs Interactive Build Wizard[/bold cyan]\n"
            "[dim]Configuração passo a passo com foco em segurança e zero vulnerabilidades[/dim]",
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
    console.print(
        "[bold yellow]? 1. Qual é o ecossistema / linguagem da sua aplicação?[/bold yellow]"
    )
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
    console.print(
        f"\n[bold yellow]? 2. Qual versão do {stack_choice} deseja utilizar?[/bold yellow]"
    )
    for i, opt in enumerate(opts, 1):
        console.print(f"  {i}. {opt}")
    _ = _prompt_choice(opts, "1")

    # 3. Base distribution
    console.print("\n[bold yellow]? 3. Qual distribuição base você prefere?[/bold yellow]")
    distros = [
        "alpine (Alpine Linux - Ultra-lightweight musl)",
        "debian (Debian Bookworm Slim - glibc)",
        "ubuntu (Ubuntu 24.04 LTS - Alta compatibilidade)",
        "distroless (Google Distroless - Sem shell, zero CVEs de SO)",
        "scratch (Scratch puro para binários estáticos)",
    ]
    for i, d in enumerate(distros, 1):
        console.print(f"  {i}. {d}")
    distro_raw = _prompt_choice(distros, "1")
    distro_key = distro_raw.split()[0].lower()

    # 4. Usar template hardened
    console.print(
        "\n[bold yellow]? 4. Utilizar template multi-stage com non-root user?[/bold yellow]"
    )
    console.print("  1. yes (Recomendado - reduz superfície de ataque)")
    console.print("  2. no (Usa Dockerfile padrão do diretório)")
    use_hardened = _prompt_choice(["yes", "no"], "1") == "yes"

    # 5. Dependências do SO / build nativo
    console.print(
        "\n[bold yellow]? 5. Sua aplicação precisa de dependências nativas do SO?[/bold yellow]"
    )
    deps_opts = [
        "none (Apenas runtime padrão)",
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
        console.input(f"\n[bold yellow]? 6. Porta da aplicação [{default_port}]: [/bold yellow]")
        or default_port
    )

    # 7. Scan pós-build
    console.print("\n[bold yellow]? 7. Executar scan de vulnerabilidades pós-build?[/bold yellow]")
    scan = _prompt_choice(["yes", "no"], "1") == "yes"

    # 8. Ciclo de auto-remediação até zero vulnerabilidades
    console.print(
        "\n[bold yellow]? 8. Ativar ciclo iterativo até ZERO vulnerabilidades?[/bold yellow]"
    )
    console.print("  1. yes (Corrige patches até eliminar CVEs)")
    console.print("  2. no (Apenas relata vulnerabilidades encontradas)")
    zero_vulns = _prompt_choice(["yes", "no"], "1") == "yes"

    # 9. Tag da imagem
    tag_input = (
        console.input("\n[bold yellow]? 9. Tag da imagem Docker [app:latest]: [/bold yellow]")
        or "app:latest"
    )

    # 10. Push para registro
    console.print("\n[bold yellow]? 10. Publicar (docker push) após aprovação?[/bold yellow]")
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
                "[bold green]✅ Validation Passed[/bold green]\n"
                "[dim]No blocking policy violations found[/dim]",
                expand=False,
            )
        )
    else:
        console.print(
            Panel(
                f"[bold red]❌ Validation Failed[/bold red]\n\n"
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
                f"[bold red]❌ Build Failed[/bold red]\n\n"
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
            f"[bold green]✅ Build Successful[/bold green]\n[dim]{response.image_tag}[/dim]",
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
        console.print(Panel("[bold yellow]💡 Hardening Suggestions[/bold yellow]", expand=False))
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
        f"✅ Validation: {validation.get('passed', 0)} passed | "
        f"⚠️ {validation.get('warnings', 0)} warnings | "
        f"❌ {validation.get('errors', 0)} errors"
    )
    console.print()

    if report.scan_results:
        console.print(Panel("[bold magenta]🔍 Security Scan Results[/bold magenta]", expand=False))
        scan_data = next(iter(report.scan_results.values()))
        console.print(f"  CRITICAL: [red]{scan_data.get('critical', 0)}[/red]")
        console.print(f"  HIGH: [red]{scan_data.get('high', 0)}[/red]")
        console.print(f"  MEDIUM: [yellow]{scan_data.get('medium', 0)}[/yellow]")
        console.print(f"  LOW: [dim]{scan_data.get('low', 0)}[/dim]")
        console.print()

    if report.remediation_history:
        console.print(Panel("[bold green]✨ Auto-Remediation Summary[/bold green]", expand=False))
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
                console.print(f"    • [dim]{action}[/dim]")
        console.print()

    if report.recommendations:
        console.print(Panel("[bold yellow]💡 Recommendations[/bold yellow]", expand=False))
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
    console.print(f"\n📄 Report saved: [cyan]{report_file}[/cyan]")


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
    <h1>🐳 DockerLs Build Report</h1>
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
    console.print(Panel(f"[bold {color}]🔗 Supply chain: {status}[/bold {color}]", expand=False))
    console.print(f"  [dim]{safe(provenance.explain())}[/dim]\n")

    source = provenance.source
    console.print("[bold]ENTRADA[/bold] [dim](medida antes do build)[/dim]")
    console.print(f"  Dockerfile  {safe(source.dockerfile) or '[dim]não digerido[/dim]'}")
    console.print(
        f"  Contexto    {safe(source.context) or '[dim]não digerido[/dim]'}"
        f"  [dim]({source.context_files} arquivos)[/dim]"
    )
    if source.git_revision:
        dirty = " [yellow](árvore suja)[/yellow]" if source.git_dirty else ""
        console.print(f"  Commit      {safe(source.git_revision)}{dirty}")
    for reference, digest in source.base_images.items():
        pinned = safe(digest) if digest else "[yellow]tag móvel, sem digest[/yellow]"
        console.print(f"  Base        {safe(reference)} -> {pinned}")

    artifact = provenance.artifact
    console.print("\n[bold]SAÍDA[/bold] [dim](medida depois do build)[/dim]")
    console.print(f"  Imagem      {safe(artifact.image_id) or '[dim]desconhecida[/dim]'}")
    if artifact.repo_digest:
        console.print(f"  Manifesto   {safe(artifact.repo_digest)}")
    if artifact.published_reference:
        console.print(f"  Publicada   {safe(artifact.published_reference)}")
    console.print()
