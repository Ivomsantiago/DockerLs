"""O caso de uso que pergunta ao registry e escreve a correção."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from dockerls.application.use_cases.upgrade_base import UpgradeBaseUseCase
from dockerls.domain.value_objects.base_upgrade import BaseStatus

_ANTIGO = "sha256:" + "a" * 64
_ATUAL = "sha256:" + "b" * 64


def _inspector(digest: str = _ATUAL):
    inspector = AsyncMock()
    inspector.resolve_digest = AsyncMock(return_value=digest)
    return inspector


@pytest.mark.asyncio
class TestUpgradeBase:
    async def test_a_stale_base_is_rewritten_in_place(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(f"FROM python:3.12@{_ANTIGO}\nUSER 1001\n")

        result = await UpgradeBaseUseCase(_inspector()).execute(tmp_path)

        assert result.applied == 1
        assert _ATUAL in dockerfile.read_text()
        assert result.outdated and result.outdated[0].status is BaseStatus.PINNED_STALE

    async def test_dry_run_touches_nothing(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        original = f"FROM python:3.12@{_ANTIGO}\n"
        dockerfile.write_text(original)

        result = await UpgradeBaseUseCase(_inspector()).execute(tmp_path, apply=False)

        assert result.applied == 0
        assert dockerfile.read_text() == original
        # O diagnóstico continua completo: é o que faz dele portão de CI.
        assert result.needs_action is True
        assert _ATUAL in result.updated_content

    async def test_a_current_base_is_left_alone(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        original = f"FROM python:3.12@{_ATUAL}\n"
        dockerfile.write_text(original)

        result = await UpgradeBaseUseCase(_inspector()).execute(tmp_path)

        assert result.applied == 0
        assert result.needs_action is False
        assert dockerfile.read_text() == original

    async def test_a_silent_registry_never_rewrites(self, tmp_path):
        # Sem resposta não há o que escrever, e o estado é UNRESOLVED --
        # nunca "em dia".
        dockerfile = tmp_path / "Dockerfile"
        original = f"FROM python:3.12@{_ANTIGO}\n"
        dockerfile.write_text(original)

        result = await UpgradeBaseUseCase(_inspector(digest="")).execute(tmp_path)

        assert result.applied == 0
        assert dockerfile.read_text() == original
        assert result.unresolved

    async def test_a_missing_dockerfile_is_an_error_not_a_pass(self, tmp_path):
        result = await UpgradeBaseUseCase(_inspector()).execute(tmp_path)
        assert result.error
        assert result.findings == []

    async def test_a_dockerfile_without_from_is_reported(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("RUN echo oi\n")
        result = await UpgradeBaseUseCase(_inspector()).execute(tmp_path)
        assert "FROM" in result.error

    async def test_every_declared_stage_is_checked(self, tmp_path):
        # Um builder velho compila com toolchain velho, e isso é problema de
        # cadeia de fornecimento mesmo que a imagem final seja endurecida.
        (tmp_path / "Dockerfile").write_text(
            f"FROM golang:1.21@{_ANTIGO} AS builder\nFROM alpine:3.20@{_ANTIGO}\n"
        )
        result = await UpgradeBaseUseCase(_inspector()).execute(tmp_path)
        assert len(result.findings) == 2
        assert result.applied == 2


@pytest.mark.asyncio
class TestTagHistoryWiring:
    """ "Esta base mudou" e "esta base muda toda semana" pedem decisões
    diferentes, e antes disto as duas produziam a mesma linha."""

    async def test_o_digest_observado_alimenta_o_historico(self, tmp_path):
        from dockerls.application.services.tag_history_store import TagHistoryStore
        from tests.unit.test_tag_history_store import FakeCache

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text(f"FROM python:3.12@{_ANTIGO}\n")
        cache = FakeCache()

        result = await UpgradeBaseUseCase(_inspector(), TagHistoryStore(cache)).execute(
            tmp_path, apply=False
        )

        historico = result.history_for(result.findings[0].base)
        assert historico is not None
        assert historico.current_digest == _ATUAL

    async def test_movimento_entre_execucoes_aparece_no_documento(self, tmp_path):
        from dockerls.application.services.tag_history_store import TagHistoryStore
        from tests.unit.test_tag_history_store import FakeCache

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\n")
        cache = FakeCache()

        await UpgradeBaseUseCase(_inspector(_ANTIGO), TagHistoryStore(cache)).execute(
            tmp_path, apply=False
        )
        result = await UpgradeBaseUseCase(_inspector(_ATUAL), TagHistoryStore(cache)).execute(
            tmp_path, apply=False
        )

        payload = result.to_dict()
        assert payload["bases"][0]["history"]["moves"] == 1

    async def test_sem_historico_o_documento_omite_a_chave_em_vez_de_mentir(self, tmp_path):
        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\n")

        result = await UpgradeBaseUseCase(_inspector()).execute(tmp_path, apply=False)

        assert result.to_dict()["bases"][0]["history"] is None

    async def test_base_irresolvivel_nao_gera_observacao(self, tmp_path):
        """Não ter conseguido perguntar não é uma observação: gravá-la
        inventaria um movimento que nunca houve."""
        from dockerls.application.services.tag_history_store import TagHistoryStore
        from tests.unit.test_tag_history_store import FakeCache

        dockerfile = tmp_path / "Dockerfile"
        dockerfile.write_text("FROM python:3.12\n")
        cache = FakeCache()

        await UpgradeBaseUseCase(_inspector(""), TagHistoryStore(cache)).execute(
            tmp_path, apply=False
        )

        assert not cache.writes
