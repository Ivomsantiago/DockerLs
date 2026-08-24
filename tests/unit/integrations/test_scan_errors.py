"""Classificação do stderr dos scanners.

`error in v...` -- um prefixo cortado da mensagem crua -- foi o que a tabela
mostrou 93 vezes seguidas. Não nomeia causa, não agrupa, não permite decidir
se vale tentar o outro scanner. A mensagem completa continua no log e no
`--format json`; o que aparece no terminal passa a ser um código estável.
"""

from __future__ import annotations

import pytest

from dockerls.domain.entities.scan_result import ScanErrorKind
from dockerls.integrations.scan_errors import classify_scanner_error

# A primeira é literalmente a saída que motivou este trabalho.
_REAL_WORLD = {
    "FATAL Fatal error run error: init error: DB error: error in vulnerability DB": (
        ScanErrorKind.DB_INIT_FAILED
    ),
    "failed to download vulnerability DB": ScanErrorKind.DB_INIT_FAILED,
    "cache may be in use by another process: timeout": ScanErrorKind.DB_INIT_FAILED,
    "unable to open database file": ScanErrorKind.DB_INIT_FAILED,
    "context deadline exceeded": ScanErrorKind.TIMEOUT,
    "analysis timed out after 300s": ScanErrorKind.TIMEOUT,
    "GET https://index.docker.io/v2/: TOOMANYREQUESTS: rate limit exceeded": (
        ScanErrorKind.RATE_LIMITED
    ),
    "unexpected status code 429": ScanErrorKind.RATE_LIMITED,
    "UNAUTHORIZED: authentication required": ScanErrorKind.AUTH_REQUIRED,
    "denied: requested access to the resource is denied": ScanErrorKind.AUTH_REQUIRED,
    "MANIFEST_UNKNOWN: manifest unknown": ScanErrorKind.NOT_FOUND,
    "no such image: node:does-not-exist": ScanErrorKind.NOT_FOUND,
    "unable to find the specified image": ScanErrorKind.NOT_FOUND,
    'FATAL image scan error: unable to find the specified image "node:does-not-exist": '
    "unable to find the specified image": ScanErrorKind.NOT_FOUND,
    "something nobody has ever seen": ScanErrorKind.UNKNOWN,
    "": ScanErrorKind.UNKNOWN,
}


class TestClassification:
    @pytest.mark.parametrize(("message", "expected"), _REAL_WORLD.items())
    def test_stderr_maps_to_a_stable_cause(self, message, expected):
        assert classify_scanner_error(message) is expected

    def test_the_db_failure_is_recognised_whatever_the_casing(self):
        for text in ("DB ERROR", "db error", "Db Error: broken"):
            assert classify_scanner_error(text) is ScanErrorKind.DB_INIT_FAILED

    def test_a_missing_image_is_not_mistaken_for_a_db_problem(self):
        """A ordem das regras importa: `not found` casaria com uma regra
        genérica se a de DB viesse antes sem qualificação."""
        assert classify_scanner_error("manifest unknown: not found") is ScanErrorKind.NOT_FOUND


class TestRetryability:
    """A classificação decide se vale tentar o outro scanner."""

    @pytest.mark.parametrize(
        "kind",
        [
            ScanErrorKind.DB_INIT_FAILED,
            ScanErrorKind.TIMEOUT,
            ScanErrorKind.RATE_LIMITED,
            ScanErrorKind.INVALID_OUTPUT,
            ScanErrorKind.SCANNER_MISSING,
            ScanErrorKind.UNKNOWN,
        ],
    )
    def test_scanner_faults_are_worth_retrying(self, kind):
        assert kind.is_scanner_fault is True

    @pytest.mark.parametrize("kind", [ScanErrorKind.NOT_FOUND, ScanErrorKind.AUTH_REQUIRED])
    def test_facts_about_the_image_are_not(self, kind):
        assert kind.is_scanner_fault is False

    def test_a_clean_scan_carries_no_error_kind(self):
        assert ScanErrorKind.NONE.is_scanner_fault is False
