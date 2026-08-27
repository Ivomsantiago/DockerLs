from __future__ import annotations

from typing import TYPE_CHECKING

from loguru import logger

from dockerls.application.services.fallback_scanner import FallbackScanner
from dockerls.integrations.grype.scanner import GrypeScanner
from dockerls.integrations.trivy.scanner import TrivyScanner

if TYPE_CHECKING:
    from pathlib import Path

    from dockerls.domain.interfaces.scanner import ScannerInterface
    from dockerls.infrastructure.evidence import EvidenceStore
    from dockerls.infrastructure.network.host_guard import HostGuard


class ScannerFactory:
    @staticmethod
    async def create(
        timeout: int = 300,
        workers: int = 1,
        cache_dir: Path | None = None,
        evidence: EvidenceStore | None = None,
        guard: HostGuard | None = None,
    ) -> ScannerInterface:
        """Build the scanner the pipeline will use.

        When both tools are installed the result is a `FallbackScanner`: the
        Trivy runs first and the Grype picks up whatever it could not measure.
        Selecting on `is_available()` alone -- which is just `shutil.which` --
        meant an installed-but-broken Trivy monopolised every scan and the
        Grype was never asked, no matter how many targets failed.
        """
        trivy = TrivyScanner(
            timeout=timeout,
            workers=workers,
            cache_dir=cache_dir,
            evidence=evidence,
            guard=guard,
        )
        grype = GrypeScanner(timeout=timeout, evidence=evidence, guard=guard, workers=workers)
        has_trivy = await trivy.is_available()
        has_grype = await grype.is_available()

        if has_trivy and has_grype:
            logger.info("Using Trivy, with Grype as per-scan fallback")
            return FallbackScanner(primary=trivy, secondary=grype)
        if has_trivy:
            logger.info("Using Trivy scanner (Grype not installed; no fallback available)")
            return trivy
        if has_grype:
            logger.info("Trivy not installed, using Grype")
            return grype

        logger.warning("No scanner available, using Trivy (commands will fail)")
        return trivy

    @staticmethod
    async def create_secondary(
        primary: ScannerInterface,
        timeout: int = 300,
        evidence: EvidenceStore | None = None,
        guard: HostGuard | None = None,
        workers: int = 1,
    ) -> ScannerInterface | None:
        """Return an *independent* scanner for cross-validation.

        Cross-validation is only meaningful between two different tools, so
        this returns None when the only available scanner is the one already
        producing the primary results.
        """
        # Um `FallbackScanner` já usa os dois: revalidar com qualquer um deles
        # confrontaria um resultado com a ferramenta que possivelmente o
        # produziu, o que não é validação independente nenhuma.
        if isinstance(primary, FallbackScanner):
            primary = primary.primary

        if isinstance(primary, GrypeScanner):
            trivy = TrivyScanner(timeout=timeout, evidence=evidence, guard=guard, workers=workers)
            return trivy if await trivy.is_available() else None

        grype = GrypeScanner(timeout=timeout, evidence=evidence, guard=guard, workers=workers)
        if await grype.is_available():
            return grype
        logger.info("Grype not installed; cross-validation disabled")
        return None
