"""A cache hit is a claim about a past scan; it must be re-validated.

1.1.0 shipped a bug where a cached entry was trusted on sight. The gate is
only worth something if it survives the shapes a real cache goes bad in:
truncated JSON, a payload from an older schema, a persisted ERROR status,
and a stale entry with no scan at all.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from dockerls.application.dto.analysis import ImageAnalysis
from dockerls.application.use_cases.recommend_images import RecommendImagesUseCase
from dockerls.domain.entities.image import DockerImage
from dockerls.domain.entities.scan_result import ScanResult, ScanStatus
from dockerls.domain.interfaces.cache_store import CacheStoreInterface
from dockerls.domain.interfaces.eol_checker import EOLCheckerInterface
from dockerls.domain.interfaces.image_repository import ImageRepositoryInterface
from dockerls.domain.interfaces.scanner import ScannerInterface

TAG = DockerImage(name="node", tag="22-alpine", is_official=True)


def _key_for(use_case) -> str:
    """A chave real que o caso de uso usa, em vez de uma cópia do formato.

    Ela carrega um fingerprint das entradas que mudam a análise (regras de
    ignore ativas, threat intel ligado ou não); um teste que reconstrói a
    string à mão passa a testar o formato, não o comportamento.
    """
    return use_case._cache_key(TAG)


class _Repo(ImageRepositoryInterface):
    async def search_tags(self, image_name, limit=100):
        return [TAG]

    async def get_image_metadata(self, image_name, tag):
        return None

    async def tag_exists(self, image_name, tag):
        return True


class _EOL(EOLCheckerInterface):
    async def is_eol(self, product, version):
        return False

    async def is_lts(self, product, version):
        return False


class _CountingScanner(ScannerInterface):
    def __init__(self):
        self.scans = 0

    async def is_available(self):
        return True

    async def scan(self, image_reference):
        self.scans += 1
        return ScanResult(
            image_reference=image_reference,
            scan_timestamp=datetime.now(tz=UTC).isoformat(),
        )


class _Cache(CacheStoreInterface):
    def __init__(self, payload, key):
        self.store = {key: payload} if payload is not None else {}
        self.deleted: list[str] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ttl_seconds=86400):
        self.store[key] = value

    async def delete(self, key):
        self.deleted.append(key)
        self.store.pop(key, None)

    async def clear(self):
        self.store.clear()


def _poisoned(status, timestamp="2026-01-01T00:00:00Z"):
    return ImageAnalysis(
        image=TAG,
        scan=ScanResult(
            image_reference=TAG.full_reference,
            status=status,
            error_message="trivy exited 1" if status != ScanStatus.OK else "",
            scan_timestamp=timestamp,
        ),
        security_score=100.0,
        tier="A",
        remediation_score=100,
    ).model_dump()


async def _run(cache_payload):
    scanner = _CountingScanner()
    use_case = RecommendImagesUseCase(
        repository=_Repo(),
        scanner=scanner,
        eol_checker=_EOL(),
    )
    key = _key_for(use_case)
    cache = _Cache(cache_payload, key)
    use_case._cache = cache
    result = await use_case.execute("node")
    return result, cache, scanner, key


class TestCorruptedPayloadsAreDiscarded:
    @pytest.mark.parametrize(
        "payload",
        [
            pytest.param({"garbage": True}, id="unknown_shape"),
            pytest.param({"image": {"name": "node"}}, id="truncated"),
            pytest.param({}, id="empty_dict"),
            pytest.param("not-a-dict", id="wrong_type"),
            pytest.param([1, 2, 3], id="list_instead_of_object"),
            pytest.param(None, id="missing"),
        ],
    )
    @pytest.mark.asyncio
    async def test_unusable_payload_forces_a_real_scan(self, payload):
        result, _, scanner, _key = await _run(payload)

        assert scanner.scans == 1, "the corrupted entry was trusted"
        assert result.recommendations
        assert result.recommendations[0].scan.is_verified

    @pytest.mark.asyncio
    async def test_schema_mismatch_is_deleted_not_reused(self):
        _, cache, _, key = await _run({"garbage": True})
        assert key in cache.deleted


class TestPersistedFailureStatusIsNeverTrusted:
    @pytest.mark.parametrize("status", [ScanStatus.ERROR, ScanStatus.TIMEOUT, ScanStatus.PARTIAL])
    @pytest.mark.asyncio
    async def test_cached_failed_scan_is_rescanned(self, status):
        result, cache, scanner, key = await _run(_poisoned(status))

        assert scanner.scans == 1, f"a cached {status.value} scan was reused"
        assert key in cache.deleted
        assert result.recommendations[0].scan.status is ScanStatus.OK

    @pytest.mark.asyncio
    async def test_cached_scan_without_a_timestamp_is_rescanned(self):
        """A default-constructed ScanResult has status OK and no timestamp
        -- the shape a "no data" fallback would persist."""
        result, cache, scanner, key = await _run(_poisoned(ScanStatus.OK, timestamp=""))

        assert scanner.scans == 1
        assert key in cache.deleted
        assert result.recommendations[0].scan.scan_timestamp != ""

    @pytest.mark.asyncio
    async def test_a_perfect_score_does_not_buy_trust(self):
        """The poisoned entries all carry score=100 / tier=S; the gate must
        key on scan status alone."""
        _, _, scanner, _key = await _run(_poisoned(ScanStatus.ERROR))
        assert scanner.scans == 1


class TestValidCacheEntriesAreStillUsed:
    """The gate must not degrade the cache into a no-op."""

    @pytest.mark.asyncio
    async def test_verified_entry_skips_the_scanner(self):
        good = ImageAnalysis(
            image=TAG,
            scan=ScanResult(
                image_reference=TAG.full_reference,
                scan_timestamp="2026-01-01T00:00:00Z",
            ),
            security_score=98.0,
            tier="A",
            remediation_score=100,
        ).model_dump()

        result, cache, scanner, _key = await _run(good)

        assert scanner.scans == 0, "a valid cache entry was ignored"
        assert cache.deleted == []
        assert result.recommendations[0].security_score == 98.0


class TestCacheKeyIsSchemaVersioned:
    def test_entries_from_an_older_schema_cannot_be_read(self, tmp_path):
        """Bumping CACHE_SCHEMA_VERSION must orphan old rows rather than
        letting them deserialize into the new shape."""
        from dockerls.cache import sqlite_cache
        from dockerls.cache.sqlite_cache import SQLiteCache

        cache = SQLiteCache(tmp_path / "cache.db")
        import asyncio

        asyncio.run(cache.set("analysis:node:22", {"security_score": 100}))

        original = sqlite_cache.CACHE_SCHEMA_VERSION
        try:
            sqlite_cache.CACHE_SCHEMA_VERSION = "v-next"
            assert asyncio.run(cache.get("analysis:node:22")) is None
        finally:
            sqlite_cache.CACHE_SCHEMA_VERSION = original

        assert asyncio.run(cache.get("analysis:node:22")) is not None


class TestCacheKeyCoversScoreAffectingInputs:
    """As regras de ignore e o threat intel são aplicados *antes* de cachear,
    então precisam entrar na chave. Sem isso o cache guardava uma supressão
    de CVE já revogada e a servia por até 24h."""

    def _use_case(self, **kwargs):
        return RecommendImagesUseCase(
            repository=_Repo(), scanner=_CountingScanner(), eol_checker=_EOL(), **kwargs
        )

    def test_changing_the_ignore_set_changes_the_key(self, tmp_path):
        ignore = tmp_path / ".dockerls-ignore.yaml"
        ignore.write_text("ignores:\n  - cve: CVE-2026-0001\n")
        with_rule = self._use_case(ignore_path=ignore)

        ignore.write_text("ignores: []\n")
        without_rule = self._use_case(ignore_path=ignore)

        assert _key_for(with_rule) != _key_for(without_rule)

    def test_an_expired_rule_does_not_reuse_the_suppressed_entry(self, tmp_path):
        """O arquivo de ignore promete que uma isenção vencida deixa de
        valer. Se a chave não mudasse, o cache desfazia essa promessa."""
        ignore = tmp_path / ".dockerls-ignore.yaml"
        ignore.write_text("ignores:\n  - cve: CVE-2026-0001\n    expires: 2999-01-01\n")
        active = self._use_case(ignore_path=ignore)

        ignore.write_text("ignores:\n  - cve: CVE-2026-0001\n    expires: 2000-01-01\n")
        expired = self._use_case(ignore_path=ignore)

        assert _key_for(active) != _key_for(expired)

    def test_toggling_threat_intel_changes_the_key(self):
        from unittest.mock import MagicMock

        assert _key_for(self._use_case()) != _key_for(self._use_case(threat_intel=MagicMock()))

    def test_the_same_inputs_give_a_stable_key(self):
        """O fingerprint não pode variar entre execuções, senão o cache
        nunca acerta."""
        assert _key_for(self._use_case()) == _key_for(self._use_case())


class _BrokenCache(CacheStoreInterface):
    """A cache whose storage is unavailable -- a locked SQLite file, a full
    disk, a read-only home directory."""

    def __init__(self, fail_on: set[str]):
        self.fail_on = fail_on

    async def get(self, key):
        if "get" in self.fail_on:
            raise OSError("database is locked")
        return None

    async def set(self, key, value, ttl_seconds=86400):
        if "set" in self.fail_on:
            raise OSError("database is locked")

    async def delete(self, key):
        if "delete" in self.fail_on:
            raise OSError("database is locked")

    async def clear(self):
        raise OSError("database is locked")


class TestStorageFailuresNeverDiscardAScan:
    """The cache is an optimisation, never a source of truth.

    A write error used to unwind into `analyze_tag`'s handler, which reports
    *scan* failures -- so a fully scanned, fully scored image was recorded as
    `ERROR`/unverified and vanished from the results because SQLite happened
    to be locked.
    """

    @pytest.mark.parametrize("failing", ["set", "get", "delete"])
    @pytest.mark.asyncio
    async def test_image_is_still_recommended(self, failing):
        scanner = _CountingScanner()
        use_case = RecommendImagesUseCase(
            repository=_Repo(),
            scanner=scanner,
            eol_checker=_EOL(),
            cache=_BrokenCache({failing}),
        )

        result = await use_case.execute("node")

        assert scanner.scans == 1
        assert result.recommendations, f"a failing cache.{failing}() dropped a verified scan"
        assert result.recommendations[0].scan.is_verified
        assert result.unverified == []


class TestCacheIsKeyedByDigestNotTag:
    """Tags são mutáveis: `node:22-alpine` de hoje não é a mesma imagem de
    ontem. Uma entrada chaveada por tag continuava servindo o resultado antigo
    por até 24h depois de um rebuild upstream -- ou seja, um veredito de
    segurança sobre bytes que não existem mais."""

    def _use_case(self):
        return RecommendImagesUseCase(
            repository=_Repo(), scanner=_CountingScanner(), eol_checker=_EOL()
        )

    def test_same_tag_different_digest_is_a_different_entry(self):
        uc = self._use_case()
        before = DockerImage(name="node", tag="22-alpine", digest="sha256:aaa")
        after = DockerImage(name="node", tag="22-alpine", digest="sha256:bbb")

        assert uc._cache_key(before) != uc._cache_key(after), (
            "a rebuilt tag reused the previous image's cached verdict"
        )

    def test_same_digest_under_different_tags_shares_the_entry(self):
        """São os mesmos bytes -- escaneá-los duas vezes é desperdício."""
        uc = self._use_case()
        a = DockerImage(name="node", tag="22-alpine", digest="sha256:aaa")
        b = DockerImage(name="node", tag="22", digest="sha256:aaa")

        assert uc._cache_key(a) == uc._cache_key(b)

    def test_it_falls_back_to_the_reference_without_a_digest(self):
        """Registries que listam só nomes de tag não dão digest; a
        referência é o melhor identificador disponível."""
        uc = self._use_case()
        image = DockerImage(name="cgr.dev/chainguard/node", tag="latest")

        assert image.full_reference in uc._cache_key(image)

    def test_different_untagged_images_still_differ(self):
        uc = self._use_case()
        a = DockerImage(name="node", tag="22-alpine")
        b = DockerImage(name="node", tag="20-alpine")

        assert uc._cache_key(a) != uc._cache_key(b)


class TestFingerprintCoversTheToolItself:
    """A cached `ImageAnalysis` carries the score, the tier and the readiness
    verdict -- all decided by policy that lives in this package. Keying only
    on the scanner meant a release that changed a penalty weight or a
    blocking rule kept serving verdicts decided under the previous rules
    until the TTL expired. `CACHE_SCHEMA_VERSION` does not catch it: the
    payload's shape is unchanged, so validation accepts it and only the
    meaning has moved.
    """

    def _use_case(self):
        return RecommendImagesUseCase(
            repository=_Repo(), scanner=_CountingScanner(), eol_checker=_EOL()
        )

    def test_the_dockerls_version_is_part_of_the_key(self, monkeypatch):
        from dockerls.application.use_cases import recommend_images as module

        use_case = self._use_case()
        before = use_case._compute_analysis_fingerprint()
        monkeypatch.setattr(module, "__version__", "999.999.999")
        after = use_case._compute_analysis_fingerprint()
        assert before != after, (
            "an upgrade that changes scoring policy must not reuse the previous "
            "release's cached verdicts"
        )

    def test_the_scanner_identity_is_still_part_of_the_key(self):
        use_case = self._use_case()
        before = use_case._compute_analysis_fingerprint()
        use_case._scanner_identity = "grype 0.90.0"
        assert use_case._compute_analysis_fingerprint() != before
