from __future__ import annotations

import asyncio
from enum import StrEnum
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.vulnerability import Severity, finding_identity

if TYPE_CHECKING:
    from dockerls.application.dto.analysis import ImageAnalysis
    from dockerls.domain.entities.scan_result import ScanResult
    from dockerls.domain.interfaces.scanner import ScannerInterface

# A second scanner never reproduces the first one's findings exactly -- the
# databases differ and each maps severities its own way. Only a difference
# that is both large in absolute terms *and* large relative to what was found
# is treated as a real disagreement worth flagging.
DEFAULT_ABS_TOLERANCE = 2
DEFAULT_REL_TOLERANCE = 0.5


class CrossValidationOutcome(StrEnum):
    """What the second opinion amounted to.

    Kept as a named outcome rather than a boolean because the three
    interesting states are not "agrees / disagrees" but "agrees",
    "differs in ways two databases normally differ", and "tells a
    different story" -- and the last of those must reach the confidence
    model, while the middle one merely stops it reaching the top.
    """

    NO_SECOND_SCANNER = "NO_SECOND_SCANNER"
    AGREEMENT = "AGREEMENT"
    MINOR_DIVERGENCE = "MINOR_DIVERGENCE"
    MATERIAL_DIVERGENCE = "MATERIAL_DIVERGENCE"


#: Severity bands compared by identity. LOW and MEDIUM are deliberately out:
#: their populations are large, the two databases classify them differently
#: as a matter of course, and comparing them would make every image look
#: disputed.
_COMPARED_SEVERITIES = (Severity.CRITICAL, Severity.HIGH)


# Validations are independent of each other, so they run concurrently. The
# cap keeps a handful of scanner processes from thrashing the machine.
DEFAULT_WORKERS = 5


#: Worst-first, so `_worse` needs no comparison table of its own.
_SEVERITY_OF_OUTCOME = {
    CrossValidationOutcome.MATERIAL_DIVERGENCE: 3,
    CrossValidationOutcome.MINOR_DIVERGENCE: 2,
    CrossValidationOutcome.AGREEMENT: 1,
    CrossValidationOutcome.NO_SECOND_SCANNER: 0,
}


def _worse(a: CrossValidationOutcome, b: CrossValidationOutcome) -> CrossValidationOutcome:
    return a if _SEVERITY_OF_OUTCOME[a] >= _SEVERITY_OF_OUTCOME[b] else b


#: How many differing findings to name before the message stops being
#: readable. The full picture is in the raw evidence of both scanners.
_MAX_EXAMPLES = 3


def _examples(identities: set[str]) -> str:
    """Name a few of the disputed findings, so the reader can go and look."""
    if not identities:
        return ""
    shown = sorted(identities)[:_MAX_EXAMPLES]
    names = ", ".join(identity.split("|", 1)[0] for identity in shown)
    more = len(identities) - len(shown)
    return f" [{names}{f', +{more} more' if more > 0 else ''}]"


class CrossValidator:
    """Re-scans top candidates with a second scanner and flags material
    disagreements, so a score is never presented at full confidence when
    two independent scanners tell different stories."""

    def __init__(
        self,
        scanner: ScannerInterface | None,
        abs_tolerance: int = DEFAULT_ABS_TOLERANCE,
        rel_tolerance: float = DEFAULT_REL_TOLERANCE,
        workers: int = DEFAULT_WORKERS,
    ):
        self._scanner = scanner
        self._abs_tolerance = abs_tolerance
        self._rel_tolerance = rel_tolerance
        self._workers = max(1, workers)

    @property
    def enabled(self) -> bool:
        return self._scanner is not None

    @property
    def scanner(self) -> ScannerInterface | None:
        return self._scanner

    async def validate(self, analyses: list[ImageAnalysis]) -> None:
        """Annotate each analysis in place with `scan_divergence` and the
        secondary scanner's evidence path.

        The DB is refreshed once before the batch, then the validations run
        concurrently -- they share no state, so serializing them only added
        latency.
        """
        if self._scanner is None or not analyses:
            return
        if not await self._scanner.is_available():
            logger.info("Cross-validation scanner unavailable; skipping")
            return

        refresh_db = getattr(self._scanner, "refresh_db", None)
        if callable(refresh_db):
            await refresh_db()

        prefetched = await self._prescan(analyses)

        semaphore = asyncio.Semaphore(self._workers)

        async def guarded(analysis: ImageAnalysis) -> None:
            async with semaphore:
                await self._validate_one(analysis, prefetched)

        await asyncio.gather(*[guarded(a) for a in analyses])

    async def _prescan(self, analyses: list[ImageAnalysis]) -> dict[str, ScanResult]:
        """Mede os finalistas de uma vez, quando a engine Go existe.

        São poucos scans -- os finalistas, não as cem candidatas --, então o
        ganho aqui é menor que no passo principal. Vale mesmo assim: é o
        mesmo caminho, e mantê-lo fora criaria uma segunda forma de
        orquestrar scans para o projeto manter.

        `{}` quando não há engine, e o caminho de sempre responde.
        """
        batch = getattr(self._scanner, "batch", None)
        if batch is None:
            return {}
        # A chave é a referência: o dedup por digest não se aplica aqui,
        # porque os finalistas já vieram deduplicados do passo principal.
        targets = [(a.image.full_reference, a.image.digest or "") for a in analyses]
        outcome = await batch.scan_batch(targets)
        if outcome is None:
            return {}
        return {
            reference: result
            for (reference, _), result in zip(targets, outcome.results, strict=True)
        }

    async def _validate_one(
        self, analysis: ImageAnalysis, prefetched: dict[str, ScanResult] | None = None
    ) -> None:
        if self._scanner is None:
            return
        reference = analysis.image.full_reference
        secondary = (prefetched or {}).get(reference)
        if secondary is None:
            secondary = await self._scanner.scan(reference)

        if not secondary.is_verified:
            logger.warning(
                f"Cross-validation of {reference} did not complete "
                f"({secondary.status.value}: {secondary.error_message or 'no details'})"
            )
            return

        if secondary.evidence_path:
            analysis.evidence_paths[secondary.scanner] = secondary.evidence_path

        outcome, description = self.compare(analysis.scan, secondary)
        analysis.cross_validation = outcome.value
        analysis.cross_validation_detail = description
        if outcome is CrossValidationOutcome.MATERIAL_DIVERGENCE:
            logger.warning(f"Material scanner divergence for {reference}: {description}")
            # `scan_divergence` remains the field the table, the exporters
            # and the confidence model already read, and it stays reserved
            # for material disagreement -- a minor one is recorded in
            # `cross_validation` without disputing the score.
            analysis.scan_divergence = description
        elif outcome is CrossValidationOutcome.MINOR_DIVERGENCE:
            logger.info(f"Minor scanner divergence for {reference}: {description}")

    def compare(
        self, primary: ScanResult, secondary: ScanResult
    ) -> tuple[CrossValidationOutcome, str]:
        """Classify two scans of the same image by *which* findings differ.

        Comparing counts alone accepted a case it should not: two scanners
        each reporting one CRITICAL, for two entirely different CVEs, agreed
        perfectly on the arithmetic while describing different images. What
        is compared here is the set of findings, so that case reads as the
        divergence it is.
        """
        parts: list[str] = []
        worst = CrossValidationOutcome.AGREEMENT

        for severity in _COMPARED_SEVERITIES:
            mine = {finding_identity(v) for v in primary.vulnerabilities if v.severity is severity}
            theirs = {
                finding_identity(v) for v in secondary.vulnerabilities if v.severity is severity
            }
            only_mine = mine - theirs
            only_theirs = theirs - mine
            if not only_mine and not only_theirs:
                continue

            magnitude = len(only_mine) + len(only_theirs)
            baseline = max(len(mine), len(theirs), 1)
            material = (
                magnitude > self._abs_tolerance and (magnitude / baseline) > self._rel_tolerance
            )
            worst = _worse(
                worst,
                CrossValidationOutcome.MATERIAL_DIVERGENCE
                if material
                else CrossValidationOutcome.MINOR_DIVERGENCE,
            )
            parts.append(
                f"{severity.value}: {primary.scanner} found {len(mine)} "
                f"({len(only_mine)} not seen by {secondary.scanner}), "
                f"{secondary.scanner} found {len(theirs)} "
                f"({len(only_theirs)} not seen by {primary.scanner})"
                + _examples(only_mine | only_theirs)
            )

        return worst, "; ".join(parts)
