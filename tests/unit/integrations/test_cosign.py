"""Assinar e verificar com cosign -- e a distinção que faz isto valer algo.

A regra acima de todas: `cosign` ausente nunca vira "não assinado". Confundir
os dois acusaria alguém por causa de uma ferramenta que faltava na máquina; na
direção oposta, uma verificação que falha em silêncio produz confiança sem
base, que é pior do que desconfiança.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import pytest

from dockerls.integrations.signing.cosign import (
    CosignClient,
    SignatureStatus,
)
from dockerls.utils.executables import ExecutableNotFoundError

_DIGEST = "reg.io/app@sha256:" + "a" * 64


def _run(code: int, out: bytes = b"", err: bytes = b""):
    return patch(
        "dockerls.integrations.signing.cosign.run_capture",
        AsyncMock(return_value=(code, out, err)),
    )


def _resolves():
    return patch(
        "dockerls.integrations.signing.cosign.resolve_executable",
        return_value="/usr/bin/cosign",
    )


def _absent():
    return patch(
        "dockerls.integrations.signing.cosign.resolve_executable",
        side_effect=ExecutableNotFoundError("cosign"),
    )


@pytest.mark.asyncio
class TestMissingSigner:
    async def test_cosign_ausente_na_verificacao_nao_e_nao_assinado(self) -> None:
        with _absent():
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.SIGNER_MISSING
        assert not result.trustworthy
        assert not result.status.is_conclusive
        assert "absence of an answer" in result.explain()

    async def test_cosign_ausente_na_assinatura_tambem(self) -> None:
        with _absent():
            result = await CosignClient().sign(_DIGEST)

        assert result.status is SignatureStatus.SIGNER_MISSING


@pytest.mark.asyncio
class TestSigning:
    async def test_assinar_por_tag_e_recusado(self) -> None:
        """Assinar uma tag assinaria o que ela aponta agora, e ela pode mover
        no instante seguinte -- a assinatura seguiria válida cobrindo outros
        bytes."""
        result = await CosignClient().sign("reg.io/app:1.0")

        assert result.status is SignatureStatus.FAILED
        assert "only digests get signed" in result.detail

    async def test_assinatura_bem_sucedida(self) -> None:
        with _resolves(), _run(0):
            result = await CosignClient().sign(_DIGEST)

        assert result.status is SignatureStatus.SIGNED

    async def test_falha_do_cosign_e_reportada_como_falha(self) -> None:
        with _resolves(), _run(1, err=b"permission denied"):
            result = await CosignClient().sign(_DIGEST)

        assert result.status is SignatureStatus.FAILED
        assert not result.trustworthy


@pytest.mark.asyncio
class TestVerification:
    async def test_assinatura_valida_revela_quem_assinou(self) -> None:
        payload = json.dumps(
            [{"optional": {"Subject": "https://github.com/org/repo/.github/workflows/x.yml"}}]
        ).encode()

        with _resolves(), _run(0, out=payload):
            result = await CosignClient().verify(
                _DIGEST,
                certificate_identity_regexp="https://github.com/org/.*",
                certificate_oidc_issuer="https://token.actions.githubusercontent.com",
            )

        assert result.status is SignatureStatus.VERIFIED
        assert result.trustworthy
        assert result.identities == ("https://github.com/org/repo/.github/workflows/x.yml",)

    async def test_verificar_sem_identidade_avisa_o_que_isso_significa(self) -> None:
        """Responde "alguém assinou", e não "quem você espera assinou"."""
        with _resolves(), _run(0, out=b"[]"):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.VERIFIED
        assert "not that whoever you expect signed" in result.detail

    async def test_ausencia_de_assinatura_e_veredito_conclusivo(self) -> None:
        with _resolves(), _run(1, err=b"error: no signatures found for image"):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.UNSIGNED
        assert result.status.is_conclusive
        assert not result.trustworthy

    async def test_falha_de_rede_nao_vira_nao_assinado(self) -> None:
        """Um é veredito sobre a imagem, o outro é falha do medidor."""
        with _resolves(), _run(1, err=b"dial tcp: connection refused"):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.FAILED
        assert not result.status.is_conclusive

    async def test_timeout_nao_vira_nao_assinado(self) -> None:
        with (
            _resolves(),
            patch(
                "dockerls.integrations.signing.cosign.run_capture",
                AsyncMock(side_effect=TimeoutError),
            ),
        ):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.FAILED

    async def test_json_ilegivel_nao_derruba_a_verificacao(self) -> None:
        with _resolves(), _run(0, out=b"nao e json"):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.VERIFIED
        assert result.identities == ()

    async def test_identidades_repetidas_aparecem_uma_vez(self) -> None:
        payload = json.dumps(
            [{"optional": {"Subject": "a@b.com"}}, {"optional": {"Subject": "a@b.com"}}]
        ).encode()

        with _resolves(), _run(0, out=payload):
            result = await CosignClient().verify(_DIGEST)

        assert result.identities == ("a@b.com",)


class TestStatusSemantics:
    def test_so_verified_autoriza_confiar(self) -> None:
        from dockerls.integrations.signing.cosign import SignatureResult

        for status in SignatureStatus:
            result = SignatureResult(reference=_DIGEST, status=status)
            assert result.trustworthy is (status is SignatureStatus.VERIFIED)

    def test_falhas_do_medidor_nao_sao_conclusivas(self) -> None:
        assert not SignatureStatus.SIGNER_MISSING.is_conclusive
        assert not SignatureStatus.FAILED.is_conclusive
        assert SignatureStatus.UNSIGNED.is_conclusive
        assert SignatureStatus.VERIFIED.is_conclusive
