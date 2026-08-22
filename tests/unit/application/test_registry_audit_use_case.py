"""Perguntar ao registry -- e distinguir "respondeu não" de "não respondeu"."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from dockerls.application.use_cases.registry_audit import RegistryAuditUseCase
from dockerls.domain.value_objects.registry_audit import AuditCheck
from dockerls.domain.value_objects.tristate import Tristate

_DIGEST = "sha256:" + "a" * 64


def _state(audit, check: AuditCheck) -> Tristate:
    return next(f.state for f in audit.findings if f.check is check)


def _inspector(mapping: dict[str, str] | None = None, *, explode: bool = False):
    mock = AsyncMock()
    table = mapping or {}

    async def resolve(image):
        if explode:
            raise RuntimeError("rede indisponível")
        return table.get(image.tag, "")

    mock.resolve_digest = AsyncMock(side_effect=resolve)
    return mock


@pytest.mark.asyncio
class TestAudit:
    async def test_tag_resolvida_e_publica(self) -> None:
        audit = await RegistryAuditUseCase(_inspector({"3.21": _DIGEST})).execute("alpine:3.21")

        assert audit.digest == _DIGEST
        assert _state(audit, AuditCheck.RESOLVABLE) is Tristate.TRUE
        assert _state(audit, AuditCheck.PUBLICLY_READABLE) is Tristate.TRUE
        assert _state(audit, AuditCheck.PINNED_REFERENCE) is Tristate.FALSE

    async def test_referencia_por_digest_e_reconhecida(self) -> None:
        audit = await RegistryAuditUseCase(_inspector()).execute(f"alpine@{_DIGEST}")

        assert _state(audit, AuditCheck.PINNED_REFERENCE) is Tristate.TRUE
        # Com digest na mão não houve consulta anônima a medir.
        assert _state(audit, AuditCheck.PUBLICLY_READABLE) is Tristate.UNKNOWN

    async def test_assinatura_encontrada_na_tag_derivada(self) -> None:
        derivada = f"{_DIGEST.replace(':', '-')}.sig"
        audit = await RegistryAuditUseCase(
            _inspector({"3.21": _DIGEST, derivada: "sha256:bb"})
        ).execute("alpine:3.21")

        assert _state(audit, AuditCheck.SIGNATURE_PRESENT) is Tristate.TRUE
        assert _state(audit, AuditCheck.ATTESTATION_PRESENT) is Tristate.FALSE

    async def test_atestacao_encontrada_na_tag_derivada(self) -> None:
        derivada = f"{_DIGEST.replace(':', '-')}.att"
        audit = await RegistryAuditUseCase(
            _inspector({"3.21": _DIGEST, derivada: "sha256:cc"})
        ).execute("alpine:3.21")

        assert _state(audit, AuditCheck.ATTESTATION_PRESENT) is Tristate.TRUE

    async def test_registry_que_nao_responde_nunca_vira_nao_assinado(self) -> None:
        audit = await RegistryAuditUseCase(_inspector(explode=True)).execute("alpine:3.21")

        assert _state(audit, AuditCheck.RESOLVABLE) is Tristate.FALSE
        assert _state(audit, AuditCheck.SIGNATURE_PRESENT) is Tristate.UNKNOWN
        assert _state(audit, AuditCheck.ATTESTATION_PRESENT) is Tristate.UNKNOWN

    async def test_referencia_vazia_nao_produz_achado_nenhum(self) -> None:
        assert not (await RegistryAuditUseCase(_inspector()).execute("")).findings


@pytest.mark.asyncio
class TestTagStability:
    async def test_sem_historico_a_estabilidade_e_desconhecida(self) -> None:
        audit = await RegistryAuditUseCase(_inspector({"3.21": _DIGEST})).execute("alpine:3.21")

        assert _state(audit, AuditCheck.TAG_STABLE) is Tristate.UNKNOWN

    async def test_tag_que_ja_mudou_e_medida_como_instavel(self) -> None:
        """A configuração de imutabilidade é uma declaração; o histórico é uma
        observação."""
        from dockerls.application.services.tag_history_store import TagHistoryStore
        from tests.unit.test_tag_history_store import FakeCache

        cache = FakeCache()
        store = TagHistoryStore(cache)
        await store.observe("alpine:3.21", "sha256:antigo")
        await store.observe("alpine:3.21", _DIGEST)

        audit = await RegistryAuditUseCase(_inspector({"3.21": _DIGEST}), store).execute(
            "alpine:3.21"
        )

        assert _state(audit, AuditCheck.TAG_STABLE) is Tristate.FALSE

    async def test_tag_que_nunca_mudou_e_medida_como_estavel(self) -> None:
        from dockerls.application.services.tag_history_store import TagHistoryStore
        from tests.unit.test_tag_history_store import FakeCache

        store = TagHistoryStore(FakeCache())
        await store.observe("alpine:3.21", _DIGEST)

        audit = await RegistryAuditUseCase(_inspector({"3.21": _DIGEST}), store).execute(
            "alpine:3.21"
        )

        assert _state(audit, AuditCheck.TAG_STABLE) is Tristate.TRUE
