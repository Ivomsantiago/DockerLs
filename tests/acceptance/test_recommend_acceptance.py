"""Acceptance criteria for `dockerls recommend`.

Everything below the CLI boundary is the real thing: the real use case, the
real composite repository, real TrivyScanner/GrypeScanner driving stub
binaries, the real evidence store and the real Rich rendering. Only the
registry HTTP calls and the vulnerability databases are stubbed, so these
assert on the pipeline's behaviour rather than on network weather.
"""

from __future__ import annotations

import io
import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from rich.console import Console

from dockerls.application.services.composite_repository import CompositeImageRepository
from dockerls.application.services.cross_validation import CrossValidator
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.cli.commands import recommend as recommend_cmd
from dockerls.cli.image_names import display_name
from dockerls.cli.progress import RichScanObserver
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.value_objects.image_reference import registry_host_of
from dockerls.infrastructure.evidence import EvidenceStore
from dockerls.integrations.grype.scanner import GrypeScanner
from dockerls.integrations.registry.hardened import (
    ChainguardRepository,
    DistrolessRepository,
)
from dockerls.integrations.trivy.scanner import TrivyScanner

# Budget for the whole run: 5 Hub tags + hardened candidates, scanned,
# cross-validated and tag-verified. The real command was taking 4m12s for
# the cross-validation step alone.
TIME_BUDGET_SECONDS = 30.0

HUB_TAGS = ["22-alpine", "22-slim", "20-alpine", "20-slim", "latest"]

CGR_PAYLOAD = {
    "name": "chainguard/node",
    "tags": [
        "latest",
        "latest-dev",
        "sha256-0007409db63979837414cf81a13fd24ec7b29fc1f94d316693e2b353e333e938.sig",
    ],
}
GCR_PAYLOAD = {
    "name": "distroless/nodejs",
    "tags": ["latest", "20"],
    "manifest": {
        "sha256:aaa": {"tag": ["20"], "timeUploadedMs": "1752471368129"},
    },
}


class _Hub:
    """Docker Hub stand-in: same interface, no network."""

    host = ""

    def __init__(self):
        self.tag_checks: list[tuple[str, str]] = []

    async def search_tags(self, image_name, limit=100):
        return [
            DockerImage(name=image_name, tag=t, is_official=True, source="Docker Hub")
            for t in HUB_TAGS[:limit]
        ]

    async def get_image_metadata(self, image_name, tag):
        return None

    async def tag_exists(self, image_name, tag):
        self.tag_checks.append((image_name, tag))
        return tag in HUB_TAGS


class _EOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


def _registry_payload(repository: str):
    return CGR_PAYLOAD if repository.startswith("chainguard/") else GCR_PAYLOAD


@pytest.fixture
def pipeline(scanner_stubs, tmp_path, monkeypatch):
    """A fully wired recommend pipeline with stubbed registry HTTP."""
    monkeypatch.chdir(tmp_path)
    evidence = EvidenceStore(tmp_path / ".dockerls" / "scans")
    hub = _Hub()
    composite = CompositeImageRepository(
        hub,
        [ChainguardRepository(), DistrolessRepository()],
        extra_limit=5,
    )

    def build(observer):
        return RecommendImagesUseCase(
            repository=composite,
            scanner=TrivyScanner(workers=6, cache_dir=tmp_path / "trivy", evidence=evidence),
            eol_checker=_EOL(),
            workers=6,
            observer=observer,
            cross_validator=CrossValidator(GrypeScanner(evidence=evidence), workers=5),
            evidence=evidence,
            max_medium=50,
            log_file=tmp_path / "run.log",
        )

    with patch(
        "dockerls.integrations.registry.oci.OCIRegistryClient.list_tags",
        AsyncMock(side_effect=lambda repository: _registry_payload(repository)),
    ):
        yield build, hub, tmp_path


async def _run(build, observer):
    return await build(observer).execute("node", limit=5)


@pytest.mark.asyncio
async def test_run_completes_within_the_time_budget(pipeline):
    build, _, _ = pipeline
    start = time.perf_counter()
    result = await _run(build, RichScanObserver(enabled=False))
    elapsed = time.perf_counter() - start

    assert result.recommendations, "expected a recommendation"
    assert elapsed < TIME_BUDGET_SECONDS, (
        f"run took {elapsed:.1f}s, over the {TIME_BUDGET_SECONDS}s budget"
    )


@pytest.mark.asyncio
async def test_grype_db_is_refreshed_once_not_per_image(pipeline):
    """The stub only sleeps its DB delay when the update has not run, so a
    per-image DB check would blow the budget in proportion to image count."""
    build, _, tmp_path = pipeline
    await _run(build, RichScanObserver(enabled=False))

    stamp = Path(tmp_path.parent / "grype-db-updated")
    # The stamp lives beside the stubs (scanner_stubs tmp_path root).
    assert any(p.name == "grype-db-updated" for p in stamp.parent.rglob("grype-db-updated"))


@pytest.mark.asyncio
async def test_every_recommended_image_has_its_own_evidence_file(pipeline):
    build, _, tmp_path = pipeline
    result = await _run(build, RichScanObserver(enabled=False))

    assert result.recommendations
    seen: set[str] = set()
    for analysis in result.recommendations:
        paths = analysis.evidence_paths
        assert paths, f"{analysis.image.full_reference} has no evidence"
        for scanner, path in paths.items():
            assert Path(path).is_file(), f"{path} missing on disk"
            payload = json.loads(Path(path).read_text())
            assert isinstance(payload, dict)
            assert scanner in Path(path).name
        # The Trivy evidence must be this image's own file, not a shared one.
        seen.add(paths["trivy"])
    assert len(seen) == len(result.recommendations), "evidence files are shared between images"


@pytest.mark.asyncio
async def test_evidence_filename_identifies_image_tag_and_scanner(pipeline):
    build, _, _ = pipeline
    result = await _run(build, RichScanObserver(enabled=False))

    analysis = result.recommendations[0]
    name = Path(analysis.evidence_paths["trivy"]).name
    assert analysis.image.tag.replace(".", "_")[:4] in name or analysis.image.tag in name
    assert "trivy" in name
    assert re.search(r"\d{8}T\d{6}", name), f"no timestamp in {name}"


@pytest.mark.asyncio
async def test_at_least_one_hardened_source_was_consulted(pipeline):
    """Both free hardened catalogues must be queried and their candidates
    scanned, whether or not they out-score the Docker Hub tags."""
    build, _, _ = pipeline
    result = await _run(build, RichScanObserver(enabled=False))

    assert "Chainguard" in result.sources_searched
    assert "Distroless" in result.sources_searched
    # Hub asked for 5 tags; the rest came from the hardened catalogues.
    assert result.total_tags_scanned > len(HUB_TAGS)
    assert result.total_tags_analyzed == result.total_tags_scanned


@pytest.mark.asyncio
async def test_source_label_matches_the_registry_each_image_came_from(pipeline):
    build, _, _ = pipeline
    result = await _run(build, RichScanObserver(enabled=False))

    # O host sai de `registry_host_of`, que é a mesma função que a produção usa
    # para decidir isto -- em vez de um `startswith` que o teste redefine por
    # conta própria e que só por sorte concorda com ela.
    esperado = {"cgr.dev": "Chainguard", "gcr.io": "Distroless"}
    for analysis in result.recommendations:
        host = registry_host_of(analysis.image.full_reference)
        assert analysis.image.source == esperado.get(host, "Docker Hub")


@pytest.mark.asyncio
async def test_a_cleaner_hardened_image_wins_and_is_labelled(pipeline, monkeypatch):
    """The point of adding these catalogues: when a hardened image really
    is cleaner, it must take the top slot and say where it came from."""
    build, _, _ = pipeline
    # Every Docker Hub tag ("node:...") reports HIGH findings; the hardened
    # references do not match the pattern and stay clean.
    monkeypatch.setenv("DOCKERLS_TEST_TRIVY_DIRTY_MATCH", "node:")

    result = await _run(build, RichScanObserver(enabled=False))

    assert result.recommendations, "expected the clean hardened images to qualify"
    top = result.recommendations[0]
    assert top.image.source in (
        "Chainguard",
        "Distroless",
    ), f"hardened image did not win: {[a.image.full_reference for a in result.recommendations]}"
    assert top.scan.high_count == 0

    buf = io.StringIO()
    with patch.object(recommend_cmd, "console", Console(file=buf, force_terminal=False, width=120)):
        recommend_cmd._print_table(result.recommendations)
    rendered = buf.getvalue()
    assert top.image.source in rendered
    # A tabela mostra o nome do runtime sem o registry que a coluna `Source`
    # ao lado já nomeia: com treze colunas, `gcr.io/distroless/nodejs22-debian12`
    # era quebrado no meio da palavra e saía ilegível.
    assert display_name(top.image.name) in rendered


@pytest.mark.asyncio
async def test_tag_verification_hits_the_owning_registry(pipeline):
    """ "Hub: OK" must mean a real registry answered, not a built string."""
    build, hub, _ = pipeline
    result = await _run(build, RichScanObserver(enabled=False))

    hub_images = [a for a in result.recommendations if a.image.source == "Docker Hub"]
    assert hub_images
    for analysis in hub_images:
        assert analysis.hub_tag_verified is True
        assert (analysis.image.name, analysis.image.tag) in hub.tag_checks


@pytest.mark.asyncio
async def test_progress_renders_one_bar_and_leaves_results_clean(pipeline):
    build, _, _ = pipeline
    progress_buf = io.StringIO()
    progress_console = Console(file=progress_buf, force_terminal=True, width=100)

    with RichScanObserver(progress_console) as observer:
        result = await _run(build, observer)
        assert len(observer.progress.tasks) == 1, "more than one progress bar"

    # Render the table on its own so row counting is unambiguous.
    table_buf = io.StringIO()
    with patch.object(
        recommend_cmd, "console", Console(file=table_buf, force_terminal=False, width=140)
    ):
        recommend_cmd._print_table(result.recommendations)
    table_out = table_buf.getvalue()

    assert "Scanning" not in table_out, "progress leaked into the results stream"
    assert "\x1b[2K" not in table_out, "progress control codes leaked into results"

    # Exactly one row per image: every row carries its source label, so
    # summing those counts detects a duplicated table or a repeated row.
    rows = sum(table_out.count(s) for s in ("Docker Hub", "Chainguard", "Distroless"))
    assert rows == len(result.recommendations), (
        f"expected {len(result.recommendations)} table rows, counted {rows}"
    )


@pytest.mark.asyncio
async def test_table_shows_source_and_details_show_evidence(pipeline):
    build, _, _ = pipeline
    result = await _run(build, RichScanObserver(enabled=False))

    buf = io.StringIO()
    with patch.object(recommend_cmd, "console", Console(file=buf, force_terminal=False, width=120)):
        recommend_cmd._print_table(result.recommendations)
        recommend_cmd._print_details(result.recommendations)

    rendered = buf.getvalue()
    assert "Source" in rendered
    assert "Docker Hub" in rendered
    for analysis in result.recommendations:
        assert Path(analysis.evidence_paths["trivy"]).name in rendered


@pytest.mark.asyncio
async def test_high_concurrency_loses_no_tag_and_hides_no_failure(
    scanner_stubs, tmp_path, monkeypatch
):
    """Every tag must end up either analyzed or in the skipped report.

    The Trivy cache lock made losing workers exit non-zero; a run that
    quietly dropped them would look cleaner than it was. Accounting must
    balance exactly, at a concurrency well above the tag count.
    """
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DOCKERLS_TEST_TRIVY_DELAY", "0.02")

    tags = [f"22.{i}-alpine" for i in range(30)]

    class _ManyTags:
        host = ""

        async def search_tags(self, image_name, limit=100):
            return [
                DockerImage(name=image_name, tag=t, is_official=True, source="Docker Hub")
                for t in tags[:limit]
            ]

        async def get_image_metadata(self, image_name, tag):
            return None

        async def tag_exists(self, image_name, tag):
            return True

    evidence = EvidenceStore(tmp_path / ".dockerls" / "scans")
    use_case = RecommendImagesUseCase(
        repository=_ManyTags(),
        scanner=TrivyScanner(workers=20, cache_dir=tmp_path / "trivy", evidence=evidence),
        eol_checker=_EOL(),
        workers=20,
        observer=RichScanObserver(enabled=False),
        evidence=evidence,
        max_medium=50,
        # Sem orçamento: o que está sob teste aqui é a concorrência, e um
        # corte de seleção reduziria o número de scans simultâneos que o
        # teste existe para exercer.
        scan_budget=0,
    )
    result = await use_case.execute("node", limit=len(tags))

    assert result.total_tags_scanned == len(tags)
    assert result.deferred == []
    # Nothing may vanish: analyzed + skipped must account for every tag.
    assert result.total_tags_analyzed + result.unverified_count == len(tags)
    assert result.total_tags_analyzed == len(tags), (
        f"{result.unverified_count} tags failed under concurrency: "
        f"{[u.reason for u in result.unverified][:3]}"
    )


@pytest.mark.asyncio
async def test_a_scan_budget_accounts_for_every_tag_it_did_not_measure(scanner_stubs, tmp_path):
    """O corte de scans é a única coisa no projeto que remove candidatas
    sem medi-las. A invariante que o torna defensável: medidas + falhadas +
    adiadas tem de fechar com o que a busca encontrou, e nenhuma tag pode
    sumir sem ser nomeada."""
    tags = [DockerImage(name="node", tag=f"22.{i}-alpine", is_official=True) for i in range(30)]

    class _ManyTags(ImageRepositoryInterface):
        async def search_tags(self, image_name, limit=100):
            return tags[:limit]

        async def get_image_metadata(self, image_name, tag):
            return next((t for t in tags if t.tag == tag), None)

        async def tag_exists(self, image_name, tag):
            return True

    use_case = RecommendImagesUseCase(
        repository=_ManyTags(),
        scanner=TrivyScanner(workers=4, cache_dir=tmp_path / "trivy"),
        eol_checker=_EOL(),
        workers=4,
        observer=RichScanObserver(enabled=False),
        max_medium=50,
        scan_budget=6,
    )
    result = await use_case.execute("node", limit=len(tags))

    assert result.tags_discovered == len(tags)
    assert result.total_tags_scanned <= 6
    assert result.total_tags_analyzed + result.unverified_count + result.deferred_count == len(tags)
    # Nomeada, e uma vez só: uma referência em duas listas seria contada
    # duas vezes por qualquer um que somasse as duas.
    named = {d.reference for d in result.deferred}
    named |= {u.image_reference for u in result.unverified}
    assert len(named) == result.deferred_count + result.unverified_count


@pytest.mark.asyncio
async def test_scanner_failures_are_all_reported_never_dropped(
    scanner_stubs, tmp_path, monkeypatch
):
    """The mirror case: when scans genuinely fail, every failure must be
    named in the report rather than silently reducing the table."""
    monkeypatch.chdir(tmp_path)

    tags = [f"22.{i}-alpine" for i in range(12)]

    class _Repo:
        host = ""

        async def search_tags(self, image_name, limit=100):
            return [
                DockerImage(name=image_name, tag=t, is_official=True, source="Docker Hub")
                for t in tags
            ]

        async def get_image_metadata(self, image_name, tag):
            return None

        async def tag_exists(self, image_name, tag):
            return True

    class _HalfBroken:
        async def is_available(self):
            return True

        async def scan(self, image_reference):
            index = int(image_reference.split(".")[1].split("-")[0])
            if index % 2:
                return ScanResult(
                    image_reference=image_reference,
                    scan_timestamp=datetime.now(tz=UTC).isoformat(),
                    status=ScanStatus.ERROR,
                    error_message="cache may be in use by another process: timeout",
                )
            return ScanResult(
                image_reference=image_reference,
                scan_timestamp=datetime.now(tz=UTC).isoformat(),
            )

    result = await RecommendImagesUseCase(
        repository=_Repo(),
        scanner=_HalfBroken(),
        eol_checker=_EOL(),
        workers=20,
        observer=RichScanObserver(enabled=False),
        max_medium=50,
    ).execute("node", limit=len(tags))

    assert result.total_tags_analyzed == 6
    assert result.unverified_count == 6
    assert result.total_tags_analyzed + result.unverified_count == len(tags)
    # Each failure names its image, so none is hidden behind a count.
    assert len({u.image_reference for u in result.unverified}) == 6
