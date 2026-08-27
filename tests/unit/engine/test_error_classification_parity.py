"""Guard: as duas implementações do classificador dão a mesma resposta.

O stderr do scanner é classificado em dois lugares -- `scan_errors.py` no
caminho Python e `errors.go` na engine -- porque classificar exige o
stderr, e o stderr só existe onde o processo foi criado. Mandá-lo de volta
para o Python custaria uma travessia por falha.

Duas implementações da mesma regra divergem, e a divergência aqui seria
particularmente ruim: a mesma falha apareceria com causas diferentes
conforme a engine estivesse instalada ou não, e a causa de uma falha não
pode depender de qual binário a mediu. A tabela em
`engine/internal/scan/testdata/error_classification.json` é lida pelos dois
testes, então um caso novo entra uma vez e cobra dos dois lados.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from dockerls.domain.entities.scan_result import ScanErrorKind
from dockerls.integrations.scan_errors import classify_scanner_error

TABLE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "engine"
    / "internal"
    / "scan"
    / "testdata"
    / "error_classification.json"
)


def _cases() -> list[tuple[str, str]]:
    if not TABLE.is_file():
        return []
    document = json.loads(TABLE.read_text(encoding="utf-8"))
    return [(c["message"], c["kind"]) for c in document["cases"]]


CASES = _cases()


@pytest.mark.skipif(not CASES, reason="shared classification table not present in this checkout")
@pytest.mark.parametrize(("message", "kind"), CASES)
def test_the_python_classifier_agrees_with_the_shared_table(message: str, kind: str) -> None:
    assert classify_scanner_error(message) is ScanErrorKind(kind)


@pytest.mark.skipif(not CASES, reason="shared classification table not present in this checkout")
def test_the_table_covers_every_cause_the_classifier_can_return() -> None:
    """Uma causa sem caso na tabela é uma regra que nenhum dos dois lados
    está conferindo."""
    covered = {kind for _, kind in CASES}
    # NONE nunca sai de uma classificação (é o default de um scan que deu
    # certo), e as três abaixo não vêm do stderr: são decididas pelo
    # próprio caminho de execução, antes de haver texto para classificar.
    not_from_stderr = {
        ScanErrorKind.NONE.value,
        ScanErrorKind.INVALID_OUTPUT.value,
        ScanErrorKind.SCANNER_MISSING.value,
        ScanErrorKind.BLOCKED_BY_POLICY.value,
    }
    expected = {kind.value for kind in ScanErrorKind} - not_from_stderr
    assert expected - covered == set()
