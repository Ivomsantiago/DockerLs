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

#: Caminho de predicado usado só como argumento; nada aqui abre arquivo.
_PREDICATE = "sbom-fixture.json"


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


@pytest.mark.asyncio
class TestVerificationFailureIsNotAbsence:
    """A distinção que este projeto inteiro existe para não perder, aplicada
    ao lado que faltava: *não assinado* e *assinado e não confere* são dois
    vereditos diferentes, e o segundo é o grave.

    O cosign anuncia uma identidade que não bate como `no matching
    signatures: none of the expected identities matched what was in the
    certificate`. O marcador `no matching signatures` também aparece numa
    imagem sem assinatura nenhuma, então quem testasse "não assinado"
    primeiro reportaria uma imagem assinada por um terceiro como se ninguém
    a tivesse assinado.
    """

    async def test_wrong_identity_is_a_verification_failure_not_unsigned(self) -> None:
        message = (
            b"Error: no matching signatures:\n"
            b"none of the expected identities matched what was in the certificate, "
            b"got subjects [attacker@evil.example] with issuer https://accounts.google.com"
        )
        with _resolves(), _run(1, err=message):
            result = await CosignClient().verify(
                _DIGEST,
                certificate_identity_regexp="https://github.com/org/.*",
                certificate_oidc_issuer="https://token.actions.githubusercontent.com",
            )

        assert result.status is SignatureStatus.VERIFICATION_FAILED
        assert result.status is not SignatureStatus.UNSIGNED
        assert not result.trustworthy
        # Veredito, não falha do medidor: um pipeline tem de poder reprovar
        # nisto, e não tratá-lo como "não se aplica".
        assert result.status.is_conclusive
        assert "VERIFICATION FAILED" in result.explain()
        assert "worse than an unsigned image" in result.explain()

    async def test_wrong_issuer_is_a_verification_failure(self) -> None:
        message = b"Error: no matching signatures:\nnone of the expected issuers matched"
        with _resolves(), _run(1, err=message):
            result = await CosignClient().verify(
                _DIGEST, certificate_oidc_issuer="https://token.actions.githubusercontent.com"
            )

        assert result.status is SignatureStatus.VERIFICATION_FAILED

    async def test_a_tampered_payload_is_a_verification_failure(self) -> None:
        """A assinatura existe e cobre outros bytes: alguém trocou a imagem."""
        with _resolves(), _run(1, err=b"Error: signature verification failed"):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.VERIFICATION_FAILED
        assert not result.trustworthy

    async def test_a_genuinely_unsigned_image_is_still_unsigned(self) -> None:
        """O contrário do teste acima: a correção não pode ter transformado
        toda ausência de assinatura numa acusação de adulteração."""
        message = b"Error: no signatures found for image\nmanifest unknown"
        with _resolves(), _run(1, err=message):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.UNSIGNED

    async def test_a_network_failure_is_neither_verdict(self) -> None:
        with _resolves(), _run(1, err=b"Error: GET https://reg.io/v2/: dial tcp: i/o timeout"):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.FAILED
        assert not result.status.is_conclusive
        assert result.status is not SignatureStatus.VERIFICATION_FAILED

    async def test_a_timeout_reports_in_english(self) -> None:
        """`detail` sai no JSON do comando; a mensagem tem de ser legível lá."""
        with (
            _resolves(),
            patch(
                "dockerls.integrations.signing.cosign.run_capture",
                AsyncMock(side_effect=TimeoutError),
            ),
        ):
            result = await CosignClient().verify(_DIGEST)

        assert result.status is SignatureStatus.FAILED
        assert result.detail.isascii()
        assert "time limit" in result.detail


@pytest.mark.asyncio
class TestVerifyPayload:
    async def test_the_json_says_whether_identity_was_constrained(self) -> None:
        """Um consumidor que só olhasse `trustworthy` não teria como saber
        que a pergunta feita foi "alguém assinou?" e não "quem?"."""
        with _resolves(), _run(0, out=b"[]"):
            loose = (await CosignClient().verify(_DIGEST)).to_dict()
        with _resolves(), _run(0, out=b"[]"):
            strict = (
                await CosignClient().verify(_DIGEST, certificate_identity_regexp="https://x/.*")
            ).to_dict()

        assert loose["identity_constrained"] is False
        assert strict["identity_constrained"] is True
        assert loose["trustworthy"] == strict["trustworthy"] is True

    async def test_the_json_separates_conclusive_from_trustworthy(self) -> None:
        with _resolves(), _run(1, err=b"none of the expected identities matched"):
            failed = (await CosignClient().verify(_DIGEST)).to_dict()
        with _absent():
            unknown = (await CosignClient().verify(_DIGEST)).to_dict()

        assert failed["status"] == "VERIFICATION_FAILED"
        assert failed["conclusive"] is True and failed["trustworthy"] is False
        assert unknown["status"] == "SIGNER_MISSING"
        assert unknown["conclusive"] is False and unknown["trustworthy"] is False

    async def test_malformed_output_under_a_constraint_is_declared(self) -> None:
        """O cosign saiu 0, então a verificação aconteceu -- mas o assinante
        não pôde ser lido de volta, e zero identidades não pode se ler como
        "não havia nenhuma"."""
        with _resolves(), _run(0, out=b"<html>gateway error</html>"):
            result = await CosignClient().verify(
                _DIGEST, certificate_identity_regexp="https://github.com/org/.*"
            )

        assert result.status is SignatureStatus.VERIFIED
        assert result.identities == ()
        assert "could not be parsed" in result.detail

    async def test_a_well_formed_empty_list_is_not_called_malformed(self) -> None:
        with _resolves(), _run(0, out=b"[]"):
            result = await CosignClient().verify(
                _DIGEST, certificate_identity_regexp="https://github.com/org/.*"
            )

        assert result.detail == ""


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
        assert SignatureStatus.VERIFICATION_FAILED.is_conclusive


class TestVerifyBlob:
    """`verify-blob` decide se uma instalação aborta, então a diferença
    entre "não confere" e "não consegui conferir" é a coisa toda: a
    primeira é veredito e para tudo; a segunda é ausência e deixa o
    checksum publicado responder."""

    @pytest.mark.asyncio
    async def test_a_clean_exit_is_a_verified_blob(self):
        with _resolves(), _run(0):
            result = await CosignClient().verify_blob(
                "f.txt", signature="f.sig", certificate="f.pem"
            )
        assert result is True

    @pytest.mark.asyncio
    async def test_a_bad_signature_is_a_verdict(self):
        with _resolves(), _run(1, err=b"error: signature verification failed"):
            result = await CosignClient().verify_blob(
                "f.txt", signature="f.sig", certificate="f.pem"
            )
        assert result is False

    @pytest.mark.asyncio
    async def test_an_identity_mismatch_is_a_verdict(self):
        """Assinado, sim -- por outra pessoa. É a falha que restringir a
        identidade existe para pegar, e ela não pode virar "inconclusivo"."""
        message = b"none of the expected identities matched what was in the certificate"
        with _resolves(), _run(1, err=message):
            result = await CosignClient().verify_blob(
                "f.txt", signature="f.sig", certificate="f.pem"
            )
        assert result is False

    @pytest.mark.asyncio
    async def test_an_unrelated_failure_is_not_a_verdict(self):
        """Rekor fora do ar não diz nada sobre os bytes."""
        message = b"error: dial tcp: lookup rekor.sigstore.dev: no such host"
        with _resolves(), _run(1, err=message):
            result = await CosignClient().verify_blob(
                "f.txt", signature="f.sig", certificate="f.pem"
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_a_missing_cosign_is_not_a_verdict(self):
        with _absent():
            result = await CosignClient().verify_blob(
                "f.txt", signature="f.sig", certificate="f.pem"
            )
        assert result is None

    @pytest.mark.asyncio
    async def test_the_identity_and_issuer_reach_the_command_line(self):
        seen: list[list[str]] = []

        async def capture(argv, timeout=None, **kwargs):
            seen.append(list(argv))
            return 0, b"", b""

        with (
            _resolves(),
            patch("dockerls.integrations.signing.cosign.run_capture", capture),
        ):
            await CosignClient().verify_blob(
                "f.txt",
                signature="f.sig",
                certificate="f.pem",
                certificate_identity_regexp="^https://github.com/anchore/grype/",
                certificate_oidc_issuer="https://token.actions.githubusercontent.com",
            )

        argv = seen[0]
        assert "verify-blob" in argv
        assert "--certificate-identity-regexp" in argv
        assert "--certificate-oidc-issuer" in argv
        assert argv[-1] == "f.txt"


class TestAttest:
    """Uma atestação é uma afirmação sobre bytes específicos -- "este SBOM
    descreve *esta* imagem". Vale a mesma regra do `sign`, e pela mesma
    razão."""

    @pytest.mark.asyncio
    async def test_a_tag_is_refused(self):
        """Atestar uma tag anexaria o documento ao que ela aponta agora, e
        ela pode mover no instante seguinte: a atestação seguiria válida,
        descrevendo outra imagem."""
        result = await CosignClient().attest(
            "reg.io/app:1.0", predicate=_PREDICATE, predicate_type="cyclonedx"
        )

        assert result.status is SignatureStatus.FAILED
        assert "only digests get attested" in result.detail

    @pytest.mark.asyncio
    async def test_a_digest_is_attested(self):
        with _resolves(), _run(0):
            result = await CosignClient().attest(
                _DIGEST, predicate=_PREDICATE, predicate_type="cyclonedx"
            )

        assert result.status is SignatureStatus.SIGNED
        assert "cyclonedx" in result.detail

    @pytest.mark.asyncio
    async def test_the_predicate_and_its_type_reach_the_command_line(self):
        """Sem `--type`, o documento é anexado como predicado genérico e
        quem consome não sabe que é um SBOM -- quase o mesmo que não ter
        anexado."""
        seen: list[list[str]] = []

        async def capture(argv, timeout=None, **kwargs):
            seen.append(list(argv))
            return 0, b"", b""

        with _resolves(), patch("dockerls.integrations.signing.cosign.run_capture", capture):
            await CosignClient().attest(_DIGEST, predicate=_PREDICATE, predicate_type="spdxjson")

        argv = seen[0]
        assert "attest" in argv
        assert argv[argv.index("--predicate") + 1] == _PREDICATE
        assert argv[argv.index("--type") + 1] == "spdxjson"
        assert argv[-1] == _DIGEST

    @pytest.mark.asyncio
    async def test_a_missing_cosign_is_an_absence_and_not_a_failure(self):
        with _absent():
            result = await CosignClient().attest(
                _DIGEST, predicate=_PREDICATE, predicate_type="cyclonedx"
            )

        assert result.status is SignatureStatus.SIGNER_MISSING

    @pytest.mark.asyncio
    async def test_a_cosign_failure_carries_the_reason(self):
        with _resolves(), _run(1, err=b"error: 401 unauthorized"):
            result = await CosignClient().attest(
                _DIGEST, predicate=_PREDICATE, predicate_type="cyclonedx"
            )

        assert result.status is SignatureStatus.FAILED
        assert "401" in result.detail
