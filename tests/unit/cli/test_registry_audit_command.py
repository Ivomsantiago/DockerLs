"""`dockerls registry-audit` -- o que o registry conta, e o que ele não conta."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

from typer.testing import CliRunner

from dockerls.cli.app import app
from dockerls.exit_codes import EXIT_ERROR, EXIT_OK, EXIT_POLICY

runner = CliRunner()

_DIGEST = "sha256:" + "a" * 64


def _resolver(mapping: dict[str, str]):
    async def resolve(image):
        return mapping.get(image.tag, "")

    return patch(
        "dockerls.integrations.registry.inspector.RegistryInspector.resolve_digest",
        AsyncMock(side_effect=resolve),
    )


def test_imagem_sem_assinatura_reprova():
    with _resolver({"3.21": _DIGEST}):
        result = runner.invoke(app, ["registry-audit", "alpine:3.21", "--no-color"])

    assert result.exit_code == EXIT_POLICY
    assert "SIGNATURE_PRESENT" in result.output


def test_imagem_assinada_e_fixada_passa():
    derivada_sig = f"{_DIGEST.replace(':', '-')}.sig"
    derivada_att = f"{_DIGEST.replace(':', '-')}.att"

    with _resolver({derivada_sig: "sha256:bb", derivada_att: "sha256:cc"}):
        result = runner.invoke(app, ["registry-audit", f"alpine@{_DIGEST}", "--no-color"])

    assert result.exit_code == EXIT_OK


def test_referencia_invalida_e_erro():
    with _resolver({}):
        result = runner.invoke(app, ["registry-audit", "", "--no-color"])

    assert result.exit_code == EXIT_ERROR


def test_acesso_publico_aparece_sem_reprovar():
    """Se ser público é problema depende de para que a imagem existe."""
    derivada_sig = f"{_DIGEST.replace(':', '-')}.sig"
    derivada_att = f"{_DIGEST.replace(':', '-')}.att"

    with _resolver({"3.21": _DIGEST, derivada_sig: "x", derivada_att: "y"}):
        result = runner.invoke(app, ["registry-audit", "alpine:3.21", "--no-color"])

    texto = " ".join(result.output.split())
    assert "PUBLICLY_READABLE" in texto
    # Só PINNED_REFERENCE alerta neste cenário: público não é alerta.
    assert "1 achado(s) que pedem atenção" in texto


def test_formato_json_traz_os_achados_e_a_ressalva():
    with _resolver({"3.21": _DIGEST}):
        result = runner.invoke(
            app, ["registry-audit", "alpine:3.21", "--format", "json", "--no-color"]
        )

    payload = json.loads(result.output)
    assert payload["digest"] == _DIGEST
    assert payload["caveat"]
    assert any(f["check"] == "SIGNATURE_PRESENT" for f in payload["findings"])
