from __future__ import annotations

import math
from typing import TYPE_CHECKING

from loguru import logger

from dockerls.domain.entities.scan_result import ScanResult, ScanStatus

if TYPE_CHECKING:
    from dockerls.domain.entities.image import DockerImage


CRITICAL_PENALTY = 20.0
HIGH_PENALTY = 5.0
MEDIUM_PENALTY = 1.0
EOL_PENALTY = 20.0
# Age is a staleness signal, not a vulnerability. Uncapped it grew by one
# point per year, so a 10-year-old image lost as much as two HIGH findings
# on age alone. Capped at 3, it can order equally-clean images without
# ever competing with measured severity.
MAX_AGE_PENALTY = 3.0
EXPLOITED_PENALTY = 10.0
# The step: a vulnerability at or above this probability draws a flat
# penalty. Kept because it is the part an operator can reason about ("EPSS
# over 0.5 costs 5 points"), and because removing it would silently change
# every score this tool has ever produced.
HIGH_EPSS_PENALTY = 5.0
HIGH_EPSS_THRESHOLD = 0.5
# The slope, added on top. The step alone made 0.97 and 0.51 cost exactly
# the same, and 0.49 cost nothing -- a cliff edge in the middle of a
# continuous measurement, where the difference between "half the time" and
# "almost certainly" is the whole point of having the number. The term is
# proportional to the probability itself and is capped well below a single
# HIGH finding, so it orders comparable images without ever competing with
# measured severity.
EPSS_SLOPE_PENALTY = 4.0

# Qualitative bonuses. Their total is deliberately held *below* the HIGH
# penalty: no amount of "official + minimal + signed + LTS + recent" may
# lift an image with an extra HIGH or CRITICAL above a cleaner one. They
# can outweigh a MEDIUM or two, which is intended -- a signed official
# distroless image with a couple of mediums is a reasonable pick over an
# unremarkable image with none.
OFFICIAL_BONUS = 1.0
MINIMAL_BASE_BONUS = 1.0
SIGNED_BONUS = 1.0
LTS_BONUS = 0.5
RECENT_BONUS = 0.5
MAX_BONUS = OFFICIAL_BONUS + MINIMAL_BASE_BONUS + SIGNED_BONUS + LTS_BONUS + RECENT_BONUS

# Scoring starts here rather than at 100 so a fully-decorated clean image
# lands exactly on 100 without being clamped. Clamping at the top was
# collapsing genuinely different images onto the same number: a clean
# image, a 1-HIGH image and a 5-MEDIUM image all read 100.0.
BASE_SCORE = 100.0 - MAX_BONUS


class SecurityScore:
    def __init__(
        self,
        image: DockerImage,
        scan: ScanResult,
        is_eol: bool = False,
        is_lts: bool = False,
    ):
        if scan.status not in (ScanStatus.OK, ScanStatus.PARTIAL):
            raise ValueError(
                f"Cannot score {image.full_reference}: scan status is "
                f"{scan.status.value} ({scan.error_message or 'no details'})"
            )
        self._image = image
        self._scan = scan
        self._is_eol = is_eol
        self._is_lts = is_lts
        self._value = self._calculate()

    @property
    def value(self) -> float:
        return self._value

    @property
    def penalty(self) -> float:
        """Everything measured about the image's vulnerabilities.

        This alone decides the ordering between images with different
        severity profiles -- the qualitative bonuses cannot overturn it for
        HIGH or CRITICAL findings.
        """
        penalty = (
            self._scan.critical_count * CRITICAL_PENALTY
            + self._scan.high_count * HIGH_PENALTY
            + self._scan.medium_count * MEDIUM_PENALTY
        )

        # CISA KEV / EPSS threat-intel signal: a vulnerability with a
        # confirmed real-world exploit (or a high predicted exploitation
        # probability) is materially worse than an unweighted CVSS count
        # suggests, so it draws an extra penalty on top of the base
        # severity penalties above.
        penalty += EXPLOITED_PENALTY * sum(1 for v in self._scan.vulnerabilities if v.exploit_known)
        penalty += HIGH_EPSS_PENALTY * sum(
            1 for v in self._scan.vulnerabilities if v.epss_score >= HIGH_EPSS_THRESHOLD
        )
        # Continuous term, over the same findings as the step. No
        # `epss_known` check is needed here and adding one would be wrong:
        # the field defaults to 0.0, so a *non-zero* score is itself proof
        # that a lookup returned it, and a zero contributes nothing either
        # way. `epss_known` earns its keep in the reporting layer, where the
        # difference between "scored at zero" and "never looked up" is a
        # statement rather than a number.
        penalty += EPSS_SLOPE_PENALTY * sum(v.epss_score for v in self._scan.vulnerabilities)

        if self._is_eol:
            penalty += EOL_PENALTY
        # Age only moves the score when the source actually reported a
        # publish date. Registries that list tag names only (Chainguard,
        # most OCI catalogues) would otherwise be charged the maximum age
        # penalty and denied the recency bonus for missing metadata.
        if self._image.age_known:
            penalty += min(self._image.age_days / 365.0, MAX_AGE_PENALTY)
        return penalty

    @property
    def bonus(self) -> float:
        """Qualitative signals, capped below a single HIGH finding."""
        bonus = 0.0
        if self._image.is_official:
            bonus += OFFICIAL_BONUS
        # Distroless, hardened-vendor (Chainguard/Wolfi/Bitnami), and Alpine
        # are all "minimal base" signals; an image matching more than one
        # must not be double-counted.
        if self._image.is_distroless or self._image.is_hardened_source or self._image.is_alpine:
            bonus += MINIMAL_BASE_BONUS
        if self._image.is_signed:
            bonus += SIGNED_BONUS
        if self._is_lts:
            bonus += LTS_BONUS
        if self._image.age_known and self._image.recently_updated:
            bonus += RECENT_BONUS
        return bonus

    def _calculate(self) -> float:
        # No "zero vulnerabilities" bonus: zero findings already means zero
        # penalty, so rewarding it again double-counted the same fact and
        # was part of what pushed clean images into the clamp.
        score = BASE_SCORE - self.penalty + self.bonus
        if not math.isfinite(score):
            # The clamp below cannot catch this: every comparison against
            # NaN is False, so `max(0.0, min(100.0, nan))` answers 100.0 --
            # the arithmetic failing produced the highest possible score.
            # Whatever went wrong, it is not evidence that the image is
            # clean, so the score collapses to the bottom and the reason is
            # loud.
            logger.error(
                f"Security score for {self._image.name}:{self._image.tag} was not a finite "
                f"number (penalty={self.penalty}, bonus={self.bonus}); reporting 0.0"
            )
            return 0.0
        return max(0.0, min(100.0, round(score, 1)))
