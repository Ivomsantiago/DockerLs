"""Guards for the two ways this tool can overload the machine it runs on.

Both were real: redaction of a scan artifact took 19 seconds of CPU per
image, and the worker count was a flat ten regardless of whether the host
had two cores or sixty-four. Neither is visible in a functional test -- the
output is identical, it just costs the machine far more than it should --
so they are pinned here as budgets.
"""

from __future__ import annotations

import json
import time

import pytest

from dockerls.infrastructure.redaction import MASK, redact
from dockerls.utils import resources


def _artifact(findings: int) -> str:
    return json.dumps(
        {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": f"CVE-2024-{i:05d}",
                            "PkgName": f"libpkg{i % 300}",
                            "Description": "x" * 400,
                        }
                        for i in range(findings)
                    ]
                }
            ]
        }
    )


class TestRedactionIsLinearEnough:
    def test_a_large_artifact_is_masked_in_reasonable_time(self):
        """The regression this pins cost 19 seconds per scanned image.

        The budget is generous -- two seconds for a document the size of a
        very noisy scan -- because the point is to catch a return to
        catastrophic backtracking, not to police milliseconds.
        """
        raw = _artifact(3000)
        start = time.monotonic()
        redact(raw)
        assert time.monotonic() - start < 2.0

    def test_cost_grows_roughly_with_size_not_explosively(self):
        """Six times the input must not cost sixty times the work."""
        small, large = _artifact(500), _artifact(3000)

        start = time.monotonic()
        redact(small)
        small_seconds = time.monotonic() - start

        start = time.monotonic()
        redact(large)
        large_seconds = time.monotonic() - start

        ratio = large_seconds / max(small_seconds, 1e-6)
        assert ratio < 20, f"redaction cost grew {ratio:.0f}x for 6x the input"

    def test_speed_did_not_come_at_the_cost_of_masking(self):
        """The whole point of the fast path is that it masks the same things."""
        document = json.dumps(
            {
                "token": "dckr_pat_AbCdEf123456789xyz",
                "x_api_key": "k-123456",
                "registry_password": "s3cr3t",
                "PkgName": "libtoken1",
                "Description": "a benign description mentioning a token in prose",
            }
        )
        redacted = redact(document)
        for secret in ("dckr_pat_AbCdEf123456789xyz", "k-123456", "s3cr3t"):
            assert secret not in redacted
        assert redacted.count(MASK) >= 3
        # A package that merely contains the word must survive: masking it
        # would destroy the finding the artifact exists to record.
        assert "libtoken1" in redacted


class TestWorkerSizing:
    def test_recommendation_fits_the_machine(self):
        recommended = resources.recommended_workers()
        assert 1 <= recommended <= resources.MAX_RECOMMENDED
        assert recommended <= max(1, int(resources.cpu_capacity()))

    def test_a_cpu_quota_narrows_the_recommendation(self, monkeypatch):
        """Inside a container the quota is what matters, not the host's cores.

        This is the common case for this tool -- it analyses containers, and
        is routinely run inside one -- and it is where reading
        `os.cpu_count()` oversubscribes worst.
        """
        monkeypatch.setattr(resources, "cpu_capacity", lambda: 0.5)
        monkeypatch.setattr(resources, "available_memory_bytes", lambda: 64 * 1024**3)
        assert resources.recommended_workers() == 1

    def test_a_memory_limit_narrows_the_recommendation(self, monkeypatch):
        monkeypatch.setattr(resources, "cpu_capacity", lambda: 64.0)
        monkeypatch.setattr(
            resources, "available_memory_bytes", lambda: 2 * resources.SCANNER_MEMORY_BYTES
        )
        assert resources.recommended_workers() == 2

    def test_a_large_machine_is_still_capped(self, monkeypatch):
        monkeypatch.setattr(resources, "cpu_capacity", lambda: 128.0)
        monkeypatch.setattr(resources, "available_memory_bytes", lambda: 512 * 1024**3)
        assert resources.recommended_workers() == resources.MAX_RECOMMENDED

    def test_unreadable_limits_never_produce_zero(self, monkeypatch):
        """A machine that answers nothing must still make progress."""
        monkeypatch.setattr(resources, "cpu_capacity", lambda: 0.0)
        monkeypatch.setattr(resources, "available_memory_bytes", lambda: None)
        assert resources.recommended_workers() >= 1

    @pytest.mark.parametrize(
        ("content", "expected"),
        [("max 100000", None), ("50000 100000", 0.5), ("200000 100000", 2.0), ("", None)],
    )
    def test_cgroup_v2_quota_is_read_as_a_fraction(self, monkeypatch, tmp_path, content, expected):
        path = tmp_path / "cpu.max"
        if content:
            path.write_text(content)
        monkeypatch.setattr(resources, "_CGROUP_V2_CPU", path)
        monkeypatch.setattr(resources, "_CGROUP_V1_QUOTA", tmp_path / "missing")
        monkeypatch.setattr(resources, "_CGROUP_V1_PERIOD", tmp_path / "missing")
        assert resources._cgroup_cpu_quota() == expected

    def test_a_sentinel_memory_limit_is_not_a_budget(self, monkeypatch, tmp_path):
        """cgroup v1 writes an enormous number to mean "no limit"."""
        path = tmp_path / "memory.limit_in_bytes"
        path.write_text("9223372036854771712")
        monkeypatch.setattr(resources, "_CGROUP_V2_MEMORY", tmp_path / "missing")
        monkeypatch.setattr(resources, "_CGROUP_V1_MEMORY", path)
        assert resources._cgroup_memory_limit() is None


class TestCoreDumpsAreDisabled:
    """Um scanner que falha um pull autenticado tem o token na memória.

    Com core dump ligado, um SIGSEGV grava esse token em disco num arquivo que
    ninguém redige -- e este projeto já redige log, evidência e exportação
    justamente para isso não acontecer.
    """

    def test_the_limiter_sets_rlimit_core_to_zero(self):
        import resource
        from unittest.mock import patch

        from dockerls.utils.subprocess_runner import _no_core_dumps

        with patch.object(resource, "setrlimit") as setrlimit:
            _no_core_dumps()
        setrlimit.assert_called_once_with(resource.RLIMIT_CORE, (0, 0))

    def test_rlimit_as_is_deliberately_not_set(self):
        # O Trivy é um binário Go, e o runtime do Go reserva um espaço de
        # endereçamento virtual enorme na largada: limitar isso mataria o
        # processo na inicialização, virando falha de scan em vez de defesa.
        import inspect

        from dockerls.utils import subprocess_runner

        source = inspect.getsource(subprocess_runner)
        assert "RLIMIT_AS" not in source.replace("`RLIMIT_AS`", "")
