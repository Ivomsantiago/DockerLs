from __future__ import annotations

from pydantic import BaseModel, Field

from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.image_facts import HardeningFacts
from dockerls.domain.entities.recommendation import Recommendation
from dockerls.domain.entities.scan_result import ScanResult
from dockerls.domain.entities.vulnerability import Vulnerability
from dockerls.domain.value_objects.confidence import Confidence
from dockerls.domain.value_objects.scan_plan import DeferredTag
from dockerls.domain.value_objects.tristate import Tristate


class DimensionReport(BaseModel):
    """A derived score plus everything needed to defend it.

    Both the hardening and attack-surface models are computed over the
    facts that could be determined, so the number alone is not enough: a
    reader needs the coverage it was computed at, and the named findings on
    either side. Carrying them together means the terminal, the JSON output
    and every exporter show the same defence of the same number.
    """

    score: float = 0.0
    #: Share of the model that could be determined, 0.0-1.0.
    coverage: float = 0.0
    #: False when coverage was too thin for the score to mean anything. The
    #: renderers show "n/a" rather than a confident-looking number.
    reportable: bool = False
    #: Determined properties that counted in the image's favour.
    positives: list[str] = Field(default_factory=list)
    #: Determined properties that counted against it.
    negatives: list[str] = Field(default_factory=list)
    #: Properties nothing could establish, named rather than omitted.
    undetermined: list[str] = Field(default_factory=list)


class ImageAnalysis(BaseModel):
    image: DockerImage
    scan: ScanResult
    security_score: float
    tier: str
    remediation_score: int
    # The domain's verdict. Written **only** by the central
    # ProductionReadiness policy (see application/services/verdict.py), never
    # by the tier: the tier can see the score and nothing else, so it cannot
    # tell a clean image from an image nobody managed to scan. Defaults to
    # False so an analysis that never reached the policy is not ready by
    # omission rather than ready by omission.
    production_ready: bool = False
    #: Stable codes for every rule the image failed (NOT_MEASURED,
    #: END_OF_LIFE, ...), so a pipeline can branch without parsing prose.
    readiness_blockers: list[str] = Field(default_factory=list)
    #: The same blockers in the reader's terms.
    readiness_reasons: list[str] = Field(default_factory=list)
    # Kept as the boolean every exporter and template already reads. It
    # answers False both for "supported" and for "nobody could tell", which
    # is why `eol_status` carries the three-valued truth beside it.
    is_eol: bool = False
    #: TRUE / FALSE / UNKNOWN. An unknown lifecycle does not penalise the
    #: score -- there is nothing to penalise -- but it is never spent as if
    #: it were a confirmation that the release is still supported.
    eol_status: Tristate = Tristate.UNKNOWN
    is_lts: bool = False
    recommendation: Recommendation | None = None
    # Set when a second scanner disagreed materially with the primary one.
    # A non-empty value means the score must be presented as disputed.
    scan_divergence: str = ""
    #: AGREEMENT / MINOR_DIVERGENCE / MATERIAL_DIVERGENCE / NO_SECOND_SCANNER.
    #: Distinct from `scan_divergence`, which stays reserved for the material
    #: case: two databases differing on a finding or two is ordinary, and
    #: calling that "disputed" would make every image look contested.
    cross_validation: str = "NO_SECOND_SCANNER"
    #: Which findings differed, named, so the disagreement can be checked.
    cross_validation_detail: str = ""
    # Docker Hub linkage. `hub_tag_verified` is deliberately tri-state:
    # True = confirmed present, False = confirmed absent, None = not checked
    # (image not on Docker Hub, or verification unavailable).
    hub_url: str = ""
    hub_tag_verified: bool | None = None
    # scanner name -> raw scan JSON path, backing the score shown above.
    evidence_paths: dict[str, str] = Field(default_factory=dict)

    # --- Multi-dimensional assessment ------------------------------------
    # The evidence record every derived dimension below is computed from,
    # carried so a consumer can recompute them or apply its own policy.
    facts: HardeningFacts = Field(default_factory=HardeningFacts)
    # How well the image is configured, independently of its CVE counts.
    hardening: DimensionReport = Field(default_factory=DimensionReport)
    # How much an attacker inherits inside the container. Higher is *worse*.
    attack_surface: DimensionReport = Field(default_factory=DimensionReport)
    # How much the evidence behind all of the above is worth. Defaults to
    # UNVERIFIED so an analysis that skipped assessment can never read as
    # trustworthy by omission.
    confidence: Confidence = Confidence.UNVERIFIED
    confidence_reasons: list[str] = Field(default_factory=list)
    # Plain-language reasons this image ranked where it did, so a
    # recommendation never reduces to an unexplained number.
    why: list[str] = Field(default_factory=list)
    # Costs and caveats of moving to this image, stated alongside the
    # reasons. A recommendation that lists only upsides is advertising.
    trade_offs: list[str] = Field(default_factory=list)
    # Set when this tag has previously been observed (by an earlier run) on
    # a *different* digest than the one just resolved. Empty when this is
    # the first time this tag was seen, or when it has stayed on the same
    # digest since. `base` already reports this for Dockerfile-pinned bases
    # (see `tag_history.py`/`base_cmd.py`); this is the same fact for a tag
    # looked up directly with `analyze`.
    tag_drift_note: str = ""

    @property
    def pinned_reference(self) -> str:
        """What to actually deploy: digest-pinned when one was resolved."""
        return self.image.pinned_reference


class BaselineCriteria(BaseModel):
    """The exact thresholds an image had to clear to count as a match.

    Carried on the result so "no image found matching baseline" can state
    what the baseline actually was instead of leaving the user to guess.
    """

    max_critical: int
    max_high: int
    max_medium: int

    def describe(self) -> str:
        return (
            f"{self.max_critical} Critical, "
            f"{self.max_high} High, "
            f"{self.max_medium} Medium (and not EOL)"
        )


class UnverifiedImage(BaseModel):
    """A tag that could not be scanned successfully.

    These never carry a score or a tier -- an image with no proof of a
    successful scan is reported as unverified, not ranked.
    """

    image_reference: str
    status: str
    reason: str
    # Causa classificada (DB_INIT_FAILED, TIMEOUT, NOT_FOUND, ...). O terminal
    # mostra isto; `reason` guarda o stderr completo para log e --format json.
    kind: str = "UNKNOWN"


class RunMetrics(BaseModel):
    """What the run actually did, as opposed to what it found.

    The pipeline already knew every one of these numbers and discarded all
    of them, so "why did that take four minutes" and "is the cache working"
    were unanswerable from the outside. They are the difference between
    tags *discovered* and scans *performed*, which the digest deduplication
    and the cache can make very different.

    Carried on the result rather than printed, so `--format json` and the
    terminal report the same figures.
    """

    tags_discovered: int = 0
    # Tags left after collapsing those that share a manifest digest. The gap
    # between this and `tags_discovered` is what deduplication saved.
    unique_digests: int = 0
    cache_hits: int = 0
    # Scanner invocations actually made, excluding cache hits and duplicates.
    scans_performed: int = 0
    cross_validations: int = 0
    workers: int = 0
    # Tags that arrived without a digest and were pinned to one. Each is a
    # registry HEAD that buys deduplication across every source.
    digests_resolved: int = 0
    # Candidates whose OCI config was fetched and verified, which is what
    # makes their hardening facts measurements rather than claims.
    images_inspected: int = 0
    #: Which scanner, at which version, produced this run's measurements.
    #: Reported rather than assumed: two runs of the same command against the
    #: same image are only comparable if this matches.
    scanner_identity: str = ""

    @property
    def duplicates_collapsed(self) -> int:
        return max(0, self.tags_discovered - self.unique_digests)

    @property
    def cache_hit_rate(self) -> float:
        """Share of candidates answered from cache, 0.0-1.0."""
        considered = self.cache_hits + self.scans_performed
        return self.cache_hits / considered if considered else 0.0


class AnalysisResult(BaseModel):
    query: str
    total_tags_scanned: int
    baseline_met: bool
    recommendations: list[ImageAnalysis] = []
    alternatives: list[ImageAnalysis] = []
    errors: list[str] = []
    # Run accounting, used to render the summary line above the table.
    total_tags_analyzed: int = 0
    unverified: list[UnverifiedImage] = []
    log_file: str = ""
    evidence_manifest: str = ""
    baseline: BaselineCriteria | None = None
    # Catalogues that returned at least one candidate for this query.
    sources_searched: list[str] = []
    metrics: RunMetrics = Field(default_factory=RunMetrics)
    #: Tags que a busca encontrou e que este run deliberadamente **não
    #: mediu**, com o motivo de cada uma. Deliberadamente separado de
    #: `unverified`: ali estão as medições que falharam, aqui as que nunca
    #: foram tentadas. As duas são ausência de medição, e nenhuma das duas
    #: é um veredito sobre a imagem -- mas confundi-las esconderia que uma
    #: é escolha desta ferramenta e a outra é uma falha.
    deferred: list[DeferredTag] = []
    #: Quantas tags a busca trouxe, antes de qualquer corte.
    tags_discovered: int = 0

    @property
    def unverified_count(self) -> int:
        return len(self.unverified)

    @property
    def deferred_count(self) -> int:
        return len(self.deferred)


class ComparisonResult(BaseModel):
    """O que a comparação mediu, e o que ela não conseguiu medir.

    `images` carrega **apenas** as imagens cujo scan completou. Uma imagem
    que ninguém conseguiu escanear não entra aqui em hipótese alguma: ela
    tem `security_score` 0.0 e tier F por construção (o fallback de
    `AnalyzeImageUseCase`), e uma linha na tabela de comparação com esses
    valores afirma que a imagem foi medida e foi mal -- que é exatamente a
    substituição que esta ferramenta existe para não fazer. As que
    falharam ficam em `unverified`, com a causa classificada.
    """

    images: list[ImageAnalysis]
    winner: str = ""
    summary: str = ""
    common_vulns: list[Vulnerability] = []
    unique_vulns: dict[str, list[Vulnerability]] = {}
    #: As referências pedidas que não puderam ser medidas, na ordem em que
    #: foram pedidas. Nunca recebem score nem tier.
    unverified: list[UnverifiedImage] = []
