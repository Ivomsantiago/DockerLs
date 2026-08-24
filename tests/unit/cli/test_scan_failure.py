"""A causa de um scan que falhou, resumida em uma linha.

O terminal despejava o stderr cru do scanner. Para uma tag inexistente o
Trivy devolve várias linhas e menciona o socket do Docker -- um daemon que
este modo de scan nem usa --, e o leitor precisava garimpar ali a única
informação que importava: a tag não existe.
"""

from __future__ import annotations

import pytest

from dockerls.cli.scan_failure import REASON_MAX_LEN, describe_scan_failure, short_reason
from dockerls.domain.entities.scan_result import ScanErrorKind

#: O stderr real do Trivy para uma tag que não existe, com o ruído que
#: motivou este resumo.
TRIVY_NOT_FOUND = (
    "2026-08-24T12:00:00Z\tFATAL\timage scan error: scan error: unable to initialize a "
    "scan service: unable to initialize an image scan service: unable to find the "
    'specified image "alpine:99.99.99" in ["docker" "containerd" "podman" "remote"]: '
    "docker error: unable to inspect the image (alpine:99.99.99): Cannot connect to the "
    "Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?"
)


class TestDescribeScanFailure:
    @pytest.mark.parametrize(
        ("kind", "expected_cause"),
        [
            (ScanErrorKind.NOT_FOUND, "tag not found on the registry"),
            (ScanErrorKind.AUTH_REQUIRED, "the registry requires credentials"),
            (ScanErrorKind.RATE_LIMITED, "rate limited by the registry"),
            (ScanErrorKind.DB_INIT_FAILED, "the vulnerability database could not be prepared"),
            (ScanErrorKind.TIMEOUT, "the scan exceeded its timeout"),
            (ScanErrorKind.SCANNER_MISSING, "no scanner executable was found"),
            (ScanErrorKind.BLOCKED_BY_POLICY, "the network policy refused this host"),
        ],
    )
    def test_a_classified_cause_becomes_a_sentence(self, kind, expected_cause):
        line = describe_scan_failure(kind, "some raw stderr nobody needs to read")
        assert line == f"{kind.value} -- {expected_cause}"

    def test_the_raw_trivy_dump_never_reaches_the_line(self):
        """O caso que motivou a mudança: a menção ao socket do Docker
        confundia quem lia, porque este modo de scan não usa o daemon."""
        line = describe_scan_failure(ScanErrorKind.NOT_FOUND, TRIVY_NOT_FOUND)

        assert line == "NOT_FOUND -- tag not found on the registry"
        assert "docker.sock" not in line
        assert "\n" not in line

    def test_an_unclassified_failure_keeps_a_readable_slice_of_the_stderr(self):
        """Pior que uma frase, melhor que nada: sem classificação, sobra o
        começo do stderr numa linha só."""
        line = describe_scan_failure(ScanErrorKind.UNKNOWN, TRIVY_NOT_FOUND)

        assert line.startswith("UNKNOWN -- ")
        assert "\n" not in line
        assert len(line) < len(TRIVY_NOT_FOUND)

    def test_an_unclassified_failure_with_no_stderr_says_so(self):
        assert describe_scan_failure(ScanErrorKind.UNKNOWN, "") == "UNKNOWN -- no details"

    def test_a_kind_given_as_a_string_is_accepted(self):
        """`UnverifiedImage.kind` é `str`, não o enum."""
        line = describe_scan_failure("NOT_FOUND", "")
        assert line == "NOT_FOUND -- tag not found on the registry"

    def test_a_kind_from_outside_the_enum_does_not_crash(self):
        """Cache antigo ou JSON de outra versão: o rótulo passa como veio,
        em vez de derrubar o comando."""
        line = describe_scan_failure("SOMETHING_NEW", "raw text")
        assert line == "SOMETHING_NEW -- raw text"


class TestShortReason:
    def test_a_multi_line_dump_collapses_to_one_line(self):
        assert "\n" not in short_reason("first line\nsecond line\n\tthird")

    def test_a_short_message_survives_intact(self):
        assert short_reason("  db error  ") == "db error"

    def test_a_long_message_is_truncated_with_an_ellipsis(self):
        collapsed = short_reason("x" * 500)
        assert len(collapsed) == REASON_MAX_LEN
        assert collapsed.endswith("...")
