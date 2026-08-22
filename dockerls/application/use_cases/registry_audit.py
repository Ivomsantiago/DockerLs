"""Perguntar ao registry o que ele conta sobre uma imagem publicada.

A metade pura está em `domain/value_objects/registry_audit.py`. Aqui mora o
que ela não pode fazer: falar com o registry.

Cada checagem é uma pergunta com resposta de três valores, e a terceira --
"não deu para perguntar" -- é a razão de este módulo existir em vez de uma
sequência de `if`. Um registry que não responde sobre a assinatura produziria,
num código com booleano, exatamente a mesma saída de um registry que respondeu
"não há assinatura". As duas frases levam a decisões opostas.

A assinatura e a atestação são procuradas onde o cosign as publica: como tags
derivadas do digest (`sha256-<hex>.sig` e `sha256-<hex>.att`). É uma convenção
do sigstore, não do OCI -- então a ausência delas significa "não está assinado
*com cosign nesse esquema*", e a explicação diz isso em vez de afirmar que
ninguém assinou nada.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.value_objects.registry_audit import (
    AuditCheck,
    AuditFinding,
    RegistryAudit,
)
from dockerls.domain.value_objects.tristate import Tristate

if TYPE_CHECKING:
    from dockerls.application.services.tag_history_store import TagHistoryStore
    from dockerls.integrations.registry.inspector import RegistryInspector


class RegistryAuditUseCase:
    """Apura o que o protocolo OCI revela sobre uma referência publicada."""

    def __init__(self, inspector: RegistryInspector, history: TagHistoryStore | None = None):
        self._inspector = inspector
        self._history = history

    async def execute(self, reference: str) -> RegistryAudit:
        name, tag, given_digest = _split(reference)
        if not name:
            return RegistryAudit(reference=reference)

        digest = given_digest or await self._digest(name, tag)
        findings = [
            AuditFinding(
                check=AuditCheck.RESOLVABLE,
                state=Tristate.of(bool(digest)),
                detail=digest,
            ),
            AuditFinding(
                check=AuditCheck.PINNED_REFERENCE,
                state=Tristate.of(bool(given_digest)),
            ),
            # O inspector fala com o registry sem nenhuma credencial. Ter
            # obtido resposta *é* a medição do acesso anônimo -- não uma
            # inferência sobre ela.
            AuditFinding(
                check=AuditCheck.PUBLICLY_READABLE,
                state=Tristate.of(bool(digest)) if not given_digest else Tristate.UNKNOWN,
            ),
            await self._tag_stability(name, tag, given_digest=bool(given_digest)),
        ]

        if digest:
            findings.append(await self._cosign_artifact(name, digest, AuditCheck.SIGNATURE_PRESENT))
            findings.append(
                await self._cosign_artifact(name, digest, AuditCheck.ATTESTATION_PRESENT)
            )
        else:
            # Sem digest não há o que procurar: reportar `UNKNOWN` é a única
            # resposta honesta, e é diferente de "não há assinatura".
            findings.append(
                AuditFinding(check=AuditCheck.SIGNATURE_PRESENT, state=Tristate.UNKNOWN)
            )
            findings.append(
                AuditFinding(check=AuditCheck.ATTESTATION_PRESENT, state=Tristate.UNKNOWN)
            )

        return RegistryAudit(reference=reference, digest=digest, findings=tuple(findings))

    async def _digest(self, name: str, tag: str) -> str:
        try:
            return await self._inspector.resolve_digest(DockerImage(name=name, tag=tag))
        except Exception as e:  # pragma: no cover - rede é o caminho instável
            logger.debug(f"Não foi possível resolver {name}:{tag}: {e}")
            return ""

    async def _tag_stability(self, name: str, tag: str, *, given_digest: bool) -> AuditFinding:
        """Se a tag já mudou de digest -- a evidência *medida* de mutabilidade.

        A configuração de imutabilidade do registry é uma declaração; o
        histórico é uma observação. Quando as duas discordam, a observação é
        que descreve o que aconteceu de fato.
        """
        if given_digest or self._history is None:
            return AuditFinding(check=AuditCheck.TAG_STABLE, state=Tristate.UNKNOWN)
        history = await self._history.get(f"{name}:{tag}")
        if history.is_empty:
            return AuditFinding(check=AuditCheck.TAG_STABLE, state=Tristate.UNKNOWN)
        return AuditFinding(
            check=AuditCheck.TAG_STABLE,
            state=Tristate.of(history.moves == 0),
            detail=history.explain(),
        )

    async def _cosign_artifact(self, name: str, digest: str, check: AuditCheck) -> AuditFinding:
        """Procura a tag derivada onde o cosign publica assinatura/atestação."""
        suffix = ".sig" if check is AuditCheck.SIGNATURE_PRESENT else ".att"
        derived = f"{digest.replace(':', '-')}{suffix}"
        try:
            found = await self._inspector.resolve_digest(DockerImage(name=name, tag=derived))
        except Exception as e:  # pragma: no cover - rede é o caminho instável
            logger.debug(f"Não foi possível consultar {derived}: {e}")
            return AuditFinding(check=check, state=Tristate.UNKNOWN)
        # "" aqui é resposta: o registry falou e não tem essa tag. O caso de
        # não conseguir falar cai no `except` acima, e vira UNKNOWN.
        return AuditFinding(check=check, state=Tristate.of(bool(found)), detail=found)


def _split(reference: str) -> tuple[str, str, str]:
    """`nome`, `tag`, `digest` -- com os vazios explícitos."""
    remainder, _, digest = reference.partition("@")
    head, slash, last = remainder.rpartition("/")
    name_part, _, tag = last.partition(":")
    name = f"{head}{slash}{name_part}"
    return name, tag or "latest", digest
