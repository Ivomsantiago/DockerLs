"""Perguntar ao registry o que cada `FROM` aponta hoje, e propor a correção.

A metade pura do trabalho está em `domain/value_objects/base_upgrade.py`. Aqui
mora a única coisa que ela não pode fazer: falar com o registry para descobrir
o digest que uma tag aponta *neste momento*.

A comparação entre esse digest e o que está escrito no Dockerfile é o que
detecta a base que apodreceu -- o caso que não avisa ninguém. Foi assim que
uma base de meados de 2024 continuou sendo construída nesta imagem por meses,
carregando duas CVEs CRITICAL do `libexpat1` que já tinham correção publicada.
O Dockerfile estava "corretamente" fixado por digest o tempo todo; fixar sem
nunca reavaliar é como trancar a porta e jogar fora o calendário.

Uma base que o registry não soube responder fica `UNRESOLVED`, nunca
"atualizada": é ausência de resposta, e o resto desta ferramenta é construído
sobre a recusa de transformar isso em afirmação.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.base_upgrade import (
    BaseFinding,
    BaseStatus,
    DeclaredBase,
    classify,
    parse_bases,
    rewrite,
)

if TYPE_CHECKING:
    from dockerls.application.services.tag_history_store import TagHistoryStore
    from dockerls.domain.value_objects.tag_history import TagHistory
    from dockerls.integrations.registry.inspector import RegistryInspector


@dataclass
class UpgradeBaseResult:
    """O que foi encontrado e, quando pedido, o que foi aplicado."""

    dockerfile: str
    findings: list[BaseFinding] = field(default_factory=list)
    #: Substituições escritas em disco. Zero em `--dry-run`, e zero também
    #: quando não havia nada a mudar.
    applied: int = 0
    #: Conteúdo resultante, escrito ou não. Serve para mostrar o diff.
    updated_content: str = ""
    error: str = ""
    #: Histórico de digests por referência (`nome:tag`), quando há onde
    #: guardá-lo. É o que transforma "esta base mudou" em "esta base muda com
    #: esta frequência" -- duas frases que pedem decisões diferentes.
    histories: dict[str, TagHistory] = field(default_factory=dict)

    @property
    def outdated(self) -> list[BaseFinding]:
        return [f for f in self.findings if f.status is BaseStatus.PINNED_STALE]

    @property
    def unpinned(self) -> list[BaseFinding]:
        return [f for f in self.findings if f.status is BaseStatus.UNPINNED]

    @property
    def unresolved(self) -> list[BaseFinding]:
        return [f for f in self.findings if f.status is BaseStatus.UNRESOLVED]

    @property
    def needs_action(self) -> bool:
        return any(f.status.needs_action for f in self.findings)

    def to_dict(self) -> dict[str, object]:
        return {
            "dockerfile": self.dockerfile,
            "applied": self.applied,
            "bases": [
                {
                    "line": f.base.line,
                    "reference": f.base.reference,
                    "stage": f.base.stage,
                    "status": str(f.status),
                    "explanation": f.explain(),
                    "current_digest": f.current_digest,
                    "proposed": f.proposed_reference,
                    "digest_arg": f.base.digest_arg,
                    "history": self._history_dict(f.base),
                }
                for f in self.findings
            ],
            "error": self.error,
        }

    def history_for(self, base: DeclaredBase) -> TagHistory | None:
        return self.histories.get(_history_key(base))

    def _history_dict(self, base: DeclaredBase) -> dict[str, object] | None:
        history = self.history_for(base)
        return history.to_dict() if history and not history.is_empty else None


def _history_key(base: DeclaredBase) -> str:
    return f"{base.name}:{base.tag or 'latest'}"


class UpgradeBaseUseCase:
    """Confere as bases de um Dockerfile contra o registry."""

    def __init__(self, inspector: RegistryInspector, history: TagHistoryStore | None = None):
        self._inspector = inspector
        self._history = history

    async def execute(
        self, dockerfile_path: str | Path, *, apply: bool = True
    ) -> UpgradeBaseResult:
        path = Path(dockerfile_path)
        if path.is_dir():
            path = path / "Dockerfile"
        if not path.is_file():
            return UpgradeBaseResult(dockerfile=str(path), error=f"Dockerfile not found at {path}")

        content = path.read_text(encoding="utf-8")
        bases = parse_bases(content)
        if not bases:
            return UpgradeBaseResult(dockerfile=str(path), error="no FROM instruction found")

        findings: list[BaseFinding] = []
        histories: dict[str, TagHistory] = {}
        for base in bases:
            digest = await self._current_digest(base)
            findings.append(classify(base, digest))
            if self._history is not None and digest:
                key = _history_key(base)
                histories[key] = await self._history.observe(key, digest)
        updated, would_apply = rewrite(content, findings)

        result = UpgradeBaseResult(
            dockerfile=str(path),
            findings=findings,
            updated_content=updated,
            histories=histories,
        )
        if apply and would_apply and updated != content:
            try:
                path.write_text(updated, encoding="utf-8")
            except OSError as e:
                # Não conseguir escrever não invalida o diagnóstico: o
                # relatório continua válido e a pessoa aplica à mão.
                result.error = f"could not write {path}: {e}"
                return result
            result.applied = would_apply
        return result

    async def _current_digest(self, base: DeclaredBase) -> str:
        """O digest que a tag aponta agora, ou "" quando não deu para perguntar."""
        name = getattr(base, "name", "")
        tag = getattr(base, "tag", "") or "latest"
        if not name:
            return ""
        try:
            return await self._inspector.resolve_digest(DockerImage(name=name, tag=tag))
        except Exception as e:  # pragma: no cover - rede é o caminho instável
            logger.debug(f"Could not resolve the digest of {name}:{tag}: {e}")
            return ""
