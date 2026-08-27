"""`dockerls verify` -- três saídas distintas, de propósito.

Sem elas um pipeline não conseguiria diferenciar "esta imagem não está
assinada" de "não deu para conferir", e trataria as duas do mesmo jeito.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY
from dockerls.integrations.signing.cosign import SignatureResult, SignatureStatus

runner = CliRunner()

_DIGEST = "reg.io/app@sha256:" + "a" * 64


def _verifies(result: SignatureResult):
    return patch(
        "dockerls.integrations.signing.cosign.CosignClient.verify",
        AsyncMock(return_value=result),
    )


def test_assinatura_valida_sai_zero():
    result = SignatureResult(
        reference=_DIGEST, status=SignatureStatus.VERIFIED, identities=("ana@x.com",)
    )

    with _verifies(result):
        outcome = runner.invoke(app, ["verify", _DIGEST, "--no-color"])

    assert outcome.exit_code == EXIT_OK
    assert "ana@x.com" in outcome.output


def test_imagem_sem_assinatura_sai_dois():
    with _verifies(SignatureResult(reference=_DIGEST, status=SignatureStatus.UNSIGNED)):
        outcome = runner.invoke(app, ["verify", _DIGEST, "--no-color"])

    assert outcome.exit_code == EXIT_POLICY


def test_cosign_ausente_sai_um_e_nao_dois():
    """Falta de ferramenta é falha técnica, não veredito sobre a imagem."""
    with _verifies(SignatureResult(reference=_DIGEST, status=SignatureStatus.SIGNER_MISSING)):
        outcome = runner.invoke(app, ["verify", _DIGEST, "--no-color"])

    assert outcome.exit_code == EXIT_ERROR
    assert "SIGNER_MISSING" in outcome.output


def test_falha_de_rede_tambem_sai_um():
    with _verifies(
        SignatureResult(
            reference=_DIGEST, status=SignatureStatus.FAILED, detail="connection refused"
        )
    ):
        outcome = runner.invoke(app, ["verify", _DIGEST, "--no-color"])

    assert outcome.exit_code == EXIT_ERROR


def test_verificar_uma_tag_avisa_que_ela_pode_mover():
    with _verifies(SignatureResult(reference="reg.io/app:1.0", status=SignatureStatus.VERIFIED)):
        outcome = runner.invoke(app, ["verify", "reg.io/app:1.0", "--no-color"])

    assert "the tag can move" in " ".join(outcome.output.split())


def test_formato_json_traz_o_veredito():
    with _verifies(SignatureResult(reference=_DIGEST, status=SignatureStatus.UNSIGNED)):
        outcome = runner.invoke(app, ["verify", _DIGEST, "--format", "json", "--no-color"])

    payload = json.loads(outcome.output)
    assert payload["status"] == "UNSIGNED"
    assert payload["trustworthy"] is False
    assert payload["explanation"]


def test_identidade_e_emissor_chegam_ao_cosign():
    captured = AsyncMock(
        return_value=SignatureResult(reference=_DIGEST, status=SignatureStatus.VERIFIED)
    )
    with patch("dockerls.integrations.signing.cosign.CosignClient.verify", captured):
        runner.invoke(
            app,
            [
                "verify",
                _DIGEST,
                "--identity",
                "https://github.com/org/.*",
                "--issuer",
                "https://token.actions.githubusercontent.com",
                "--no-color",
            ],
        )

    kwargs = captured.await_args.kwargs
    assert kwargs["certificate_identity_regexp"] == "https://github.com/org/.*"
    assert kwargs["certificate_oidc_issuer"] == "https://token.actions.githubusercontent.com"
