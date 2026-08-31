"""O fallback para o Grype só existia na *escolha* do scanner.

`ScannerFactory` olhava `is_available()` -- que é `shutil.which(...)` -- e, se
o binário do Trivy estivesse no PATH, o Grype nunca mais entrava na conversa.
Um Trivy instalado porém quebrado (DB corrompida, sem rede para baixá-la,
timeout) não acionava fallback nenhum: 93 tags de 115 eram marcadas como não
verificadas, uma a uma, sem que a segunda ferramenta fosse sequer consultada.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from dockerls.application.services.fallback_scanner import FallbackScanner
from dockerls.application.services.scanner_factory import ScannerFactory
from dockerls.domain.entities.scan_result import ScanErrorKind, ScanResult, ScanStatus
from dockerls.domain.interfaces.scanner import ScannerInterface
from dockerls.integrations.grype.scanner import GrypeScanner
from dockerls.integrations.trivy.scanner import TrivyScanner


def _ok(scanner: str) -> ScanResult:
    return ScanResult(
        image_reference="node:22-alpine",
        scanner=scanner,
        scan_timestamp=datetime.now(tz=UTC).isoformat(),
    )


def _failed(scanner: str, kind: ScanErrorKind, message: str = "boom") -> ScanResult:
    return ScanResult(
        image_reference="node:22-alpine",
        scanner=scanner,
        scan_timestamp=datetime.now(tz=UTC).isoformat(),
        status=ScanStatus.ERROR,
        error_message=message,
        error_kind=kind,
    )


class _Stub(ScannerInterface):
    def __init__(self, result: ScanResult, available: bool = True):
        self._result = result
        self._available = available
        self.calls = 0

    async def is_available(self) -> bool:
        return self._available

    async def scan(self, image_reference: str) -> ScanResult:
        self.calls += 1
        return self._result


class TestFallbackFiresOnScannerFaults:
    """A condição de acionamento é a *causa* da falha, não a ausência do
    binário."""

    @pytest.mark.parametrize(
        "kind",
        [
            ScanErrorKind.DB_INIT_FAILED,
            ScanErrorKind.TIMEOUT,
            ScanErrorKind.INVALID_OUTPUT,
            ScanErrorKind.RATE_LIMITED,
            ScanErrorKind.UNKNOWN,
        ],
    )
    @pytest.mark.asyncio
    async def test_scanner_side_failure_is_retried_with_the_secondary(self, kind):
        primary = _Stub(_failed("trivy", kind))
        secondary = _Stub(_ok("grype"))

        result = await FallbackScanner(primary, secondary).scan("node:22-alpine")

        assert secondary.calls == 1, f"{kind.value} did not trigger the fallback"
        assert result.is_verified
        assert result.scanner == "grype"

    @pytest.mark.parametrize("kind", [ScanErrorKind.NOT_FOUND, ScanErrorKind.AUTH_REQUIRED])
    @pytest.mark.asyncio
    async def test_facts_about_the_image_are_not_retried(self, kind):
        """Perguntar de novo, a outra ferramenta, só dobra a espera pela
        mesma resposta."""
        primary = _Stub(_failed("trivy", kind))
        secondary = _Stub(_ok("grype"))

        result = await FallbackScanner(primary, secondary).scan("node:22-alpine")

        assert secondary.calls == 0
        assert result.error_kind is kind

    @pytest.mark.asyncio
    async def test_a_successful_primary_never_calls_the_secondary(self):
        primary = _Stub(_ok("trivy"))
        secondary = _Stub(_ok("grype"))

        result = await FallbackScanner(primary, secondary).scan("node:22-alpine")

        assert secondary.calls == 0
        assert result.scanner == "trivy"

    @pytest.mark.asyncio
    async def test_both_failing_keeps_the_primary_diagnosis(self):
        primary = _Stub(_failed("trivy", ScanErrorKind.DB_INIT_FAILED, "trivy db broken"))
        secondary = _Stub(_failed("grype", ScanErrorKind.TIMEOUT, "grype timed out"))

        result = await FallbackScanner(primary, secondary).scan("node:22-alpine")

        assert result.scanner == "trivy"
        assert "trivy db broken" in result.error_message

    @pytest.mark.asyncio
    async def test_missing_secondary_binary_is_not_a_crash(self):
        primary = _Stub(_failed("trivy", ScanErrorKind.DB_INIT_FAILED))
        secondary = _Stub(_ok("grype"), available=False)

        result = await FallbackScanner(primary, secondary).scan("node:22-alpine")

        assert secondary.calls == 0
        assert result.error_kind is ScanErrorKind.DB_INIT_FAILED

    @pytest.mark.asyncio
    async def test_it_counts_what_the_secondary_rescued(self):
        """Contabilidade para o resumo da execução: quantas tags só existem
        no resultado porque o segundo scanner respondeu."""
        fallback = FallbackScanner(
            _Stub(_failed("trivy", ScanErrorKind.DB_INIT_FAILED)), _Stub(_ok("grype"))
        )
        await fallback.scan("node:22-alpine")
        await fallback.scan("node:22-alpine")

        assert fallback.fallback_attempts == 2
        assert fallback.fallback_successes == 2


class TestFactoryWiresTheFallback:
    @pytest.mark.asyncio
    async def test_both_installed_yields_a_fallback_scanner(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}")

        scanner = await ScannerFactory.create()

        assert isinstance(scanner, FallbackScanner)
        assert isinstance(scanner.primary, TrivyScanner)
        assert isinstance(scanner.secondary, GrypeScanner)

    @pytest.mark.asyncio
    async def test_only_trivy_installed_yields_trivy_alone(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/bin/trivy" if name == "trivy" else None)

        scanner = await ScannerFactory.create()

        assert isinstance(scanner, TrivyScanner)

    @pytest.mark.asyncio
    async def test_only_grype_installed_yields_grype(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/bin/grype" if name == "grype" else None)

        scanner = await ScannerFactory.create()

        assert isinstance(scanner, GrypeScanner)

    @pytest.mark.asyncio
    async def test_cross_validation_looks_past_the_fallback_wrapper(self, monkeypatch):
        """Revalidar com um dos dois scanners que já produziram o resultado
        não é validação independente nenhuma."""
        monkeypatch.setattr("shutil.which", lambda name: f"/usr/local/bin/{name}")
        primary = await ScannerFactory.create()

        secondary = await ScannerFactory.create_secondary(primary)

        assert isinstance(secondary, GrypeScanner)


class _SlowRefresh(ScannerInterface):
    """A scanner whose DB download takes measurable time, so refresh order
    can be observed."""

    def __init__(self, name: str, delay: float, log: list[str]):
        self._name = name
        self._delay = delay
        self._log = log

    async def is_available(self) -> bool:
        return True

    async def scan(self, image_reference: str) -> ScanResult:  # pragma: no cover - unused here
        raise NotImplementedError

    async def refresh_db(self) -> bool:
        self._log.append(f"{self._name}-start")
        await asyncio.sleep(self._delay)
        self._log.append(f"{self._name}-end")
        return True


class TestFallbackRefreshDbRunsInParallel:
    """The primary and secondary DB downloads used to run one after the
    other; a run that never needed the secondary still paid for both in
    sequence."""

    @pytest.mark.asyncio
    async def test_both_downloads_overlap(self):
        log: list[str] = []
        primary = _SlowRefresh("primary", delay=0.05, log=log)
        secondary = _SlowRefresh("secondary", delay=0.05, log=log)
        fallback = FallbackScanner(primary, secondary)

        ok = await fallback.refresh_db()

        assert ok is True
        # Sequential would read primary-start, primary-end, secondary-start,
        # secondary-end. Overlapping, secondary starts before primary ends.
        assert log.index("secondary-start") < log.index("primary-end")

    @pytest.mark.asyncio
    async def test_primary_result_is_returned_even_if_secondary_fails(self):
        class _Failing(ScannerInterface):
            async def is_available(self) -> bool:
                return True

            async def scan(self, image_reference: str) -> ScanResult:  # pragma: no cover
                raise NotImplementedError

            async def refresh_db(self) -> bool:
                return False

        log: list[str] = []
        fallback = FallbackScanner(_SlowRefresh("primary", 0.0, log), _Failing())

        assert await fallback.refresh_db() is True
