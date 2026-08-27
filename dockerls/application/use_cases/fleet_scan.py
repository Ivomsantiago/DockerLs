"""Percorrer uma árvore de repositórios e ler todo Dockerfile que houver.

A metade pura está em `domain/value_objects/fleet.py`. Aqui mora o que ela não
pode fazer: andar no disco.

Andar no disco é justamente onde este comando pode se machucar, e três limites
existem por isso:

* **Nada de symlink.** Um link para `/` transformaria uma varredura de um
  repositório numa varredura da máquina inteira, e um link para fora da árvore
  faria o relatório falar de arquivos que não pertencem a ela.
* **Teto de arquivos e de profundidade.** Uma varredura que roda por vinte
  minutos é uma varredura que ninguém roda de novo. Quando o teto é atingido o
  relatório **diz que foi truncado** -- um retrato parcial que se apresenta
  como completo é pior do que nenhum retrato.
* **Diretórios de dependência ficam de fora.** Os `Dockerfile` dentro de
  `node_modules` ou de um `.venv` são de terceiros: incluí-los enche o
  relatório de linhas sobre as quais ninguém pode agir, e a lista deixa de ser
  fila de trabalho.

Um arquivo que não pôde ser lido vira entrada com erro, nunca desaparece do
relatório: sumir com o ilegível faria a frota parecer menor e mais em ordem do
que é.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.dockerfile_analysis import (
    DockerfileAnalysis,
    ValidationStatus,
)
from dockerls.domain.value_objects.base_upgrade import parse_bases
from dockerls.domain.value_objects.build_policy import (
    BaseFact,
    PolicyFacts,
    PolicyViolation,
    evaluate,
)
from dockerls.domain.value_objects.fleet import FleetEntry, FleetReport
from dockerls.domain.value_objects.image_reference import registry_host_of
from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from dockerls.domain.interfaces.dockerfile_validator import DockerfileValidatorInterface
    from dockerls.domain.value_objects.build_policy import BuildPolicy

#: Nomes reconhecidos como Dockerfile. `Dockerfile.prod`, `Dockerfile.hardened`
#: e afins entram: são arquivos que constroem imagens de verdade, e deixá-los
#: de fora esconderia exatamente as variantes que ninguém revisa.
_DOCKERFILE_PREFIX = "dockerfile"

#: Diretórios pulados sempre. São dependências de terceiros ou artefatos.
_SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".tox",
        ".venv",
        "venv",
        "node_modules",
        "vendor",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        "target",
        ".terraform",
    }
)

MAX_DOCKERFILES = 2_000
MAX_DEPTH = 12


@dataclass
class FleetScanRequest:
    root: str
    policy: BuildPolicy | None = None
    max_dockerfiles: int = MAX_DOCKERFILES
    max_depth: int = MAX_DEPTH


class FleetScanUseCase:
    """Lê todo Dockerfile sob uma raiz e monta o retrato agregado."""

    def __init__(self, validator: DockerfileValidatorInterface):
        self._validator = validator

    def execute(self, request: FleetScanRequest) -> FleetReport:
        root = Path(request.root)
        if not root.is_dir():
            return FleetReport(root=str(root), unreadable_paths=(str(root),))

        found, truncated, unreadable = _walk(
            root, max_files=request.max_dockerfiles, max_depth=request.max_depth
        )
        # A política estática é um subconjunto: as regras que dependem de scan
        # continuam valendo no `build`, e aplicá-las aqui produziria uma
        # violação idêntica por arquivo -- uma lista toda vermelha não
        # distingue nada.
        static = request.policy.static_subset() if request.policy else None

        entries = tuple(self._read(path, root, static) for path in found)
        return FleetReport(
            root=str(root),
            entries=entries,
            unreadable_paths=unreadable,
            truncated=truncated,
            policy_applied=request.policy is not None,
        )

    def _read(self, path: Path, root: Path, policy: BuildPolicy | None) -> FleetEntry:
        relative = _relative(path, root)
        try:
            analysis = self._validator.analyze(str(path))
        except Exception as e:
            # Um arquivo ilegível continua no relatório: sumir com ele faria a
            # frota parecer menor e mais em ordem do que é.
            logger.debug(f"Could not analyze {path}: {e}")
            return FleetEntry(path=relative, error=str(e) or "could not be analyzed")

        info = analysis.info
        nonroot = _nonroot(analysis)

        # As bases saem do `parse_bases`, não de `info.base_images`: ele
        # expande os `ARG`, e sem isso um `FROM python:3.12@${PYTHON_DIGEST}`
        # -- que é a forma *correta* de fixar -- seria contado como não
        # fixado. Uma varredura que reprova quem fez certo é uma varredura que
        # ensina a fazer errado.
        try:
            declared = parse_bases(path.read_text(encoding="utf-8", errors="replace"))
        except OSError as e:
            logger.debug(f"Could not re-read {path}: {e}")
            declared = []

        facts = tuple(
            BaseFact(
                reference=base.reference,
                registry=registry_host_of(base.name),
                pinned=base.is_pinned,
            )
            for base in declared
        )
        bases = tuple(fact.reference for fact in facts)
        pinned = sum(1 for fact in facts if fact.pinned)

        violations: tuple[PolicyViolation, ...] = ()
        if policy is not None:
            violations = tuple(
                evaluate(
                    policy,
                    PolicyFacts(bases=facts, labels=dict(info.labels), nonroot=nonroot),
                )
            )

        return FleetEntry(
            path=relative,
            bases=bases,
            pinned_bases=pinned,
            total_bases=len(facts),
            nonroot=nonroot,
            stages=info.stages,
            violations=violations,
        )


def _nonroot(analysis: DockerfileAnalysis) -> Tristate:
    """O veredito do DF002, ou `UNKNOWN` quando a checagem não está lá.

    A ausência é `UNKNOWN` e não `FALSE`: não ter medido não é ter medido e
    reprovado, e a frota conta os dois em colunas separadas justamente porque
    a fila de trabalho de cada um é diferente.
    """
    for check in analysis.validation.checks:
        if check.rule_id == "DF002":
            return Tristate.of(check.status is ValidationStatus.PASS)
    return Tristate.UNKNOWN


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:  # pragma: no cover - a varredura nunca sai da raiz
        return str(path)


def _walk(
    root: Path, *, max_files: int, max_depth: int
) -> tuple[list[Path], bool, tuple[str, ...]]:
    """Os Dockerfiles sob `root`, ordenados, sem seguir symlink."""
    found: list[Path] = []
    unreadable: list[str] = []
    truncated = False
    stack: list[tuple[Path, int]] = [(root, 0)]

    while stack:
        directory, depth = stack.pop()
        if depth > max_depth:
            truncated = True
            continue
        try:
            children = sorted(directory.iterdir())
        except OSError as e:
            logger.debug(f"Could not list {directory}: {e}")
            unreadable.append(_relative(directory, root))
            continue

        for child in children:
            # Symlinks nunca são seguidos: um link para `/` transformaria a
            # varredura de um repositório numa varredura da máquina.
            if child.is_symlink():
                continue
            if child.is_dir():
                if child.name not in _SKIPPED_DIRECTORIES:
                    stack.append((child, depth + 1))
            elif _is_dockerfile(child.name):
                if len(found) >= max_files:
                    truncated = True
                    continue
                found.append(child)

    found.sort()
    return found, truncated, tuple(sorted(unreadable))


def _is_dockerfile(name: str) -> bool:
    lowered = name.lower()
    if lowered == _DOCKERFILE_PREFIX or lowered.startswith(f"{_DOCKERFILE_PREFIX}."):
        return True
    # `app.Dockerfile` é a outra convenção comum, e ignorá-la deixaria de fora
    # repositórios inteiros que a usam.
    return lowered.endswith(f".{_DOCKERFILE_PREFIX}")
