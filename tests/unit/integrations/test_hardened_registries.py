from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from dockerls.integrations.registry.hardened import (
    ChainguardRepository,
    DistrolessRepository,
)
from dockerls.integrations.registry.oci import (
    is_runnable_tag,
    parse_www_authenticate,
)
from dockerls.integrations.registry.urls import source_url


class TestRunnableTagFilter:
    @pytest.mark.parametrize(
        "tag",
        [
            "sha256-0007409db63979837414cf81a13fd24ec7b29fc1f94d316693e2b353e333e938.att",
            "sha256-0007409db63979837414cf81a13fd24ec7b29fc1f94d316693e2b353e333e938.sig",
            "sha256-0029ab60fc5abc516a83ba50edadcee03226d8072d39ab1b44455ee8ba3448c9.sbom",
            "deprecated-public-image-0018692cf052c1e30ad91683d349070c04ddaed118af5d",
        ],
    )
    def test_cosign_artifacts_are_not_images(self, tag):
        """cgr.dev publishes ~1000 of these per repo; they are signatures
        and SBOMs, not anything a scanner can pull."""
        assert is_runnable_tag(tag) is False

    @pytest.mark.parametrize("tag", ["16-amd64", "16-debug-arm64", "debug-nonroot-riscv64"])
    def test_single_arch_aliases_are_skipped(self, tag):
        assert is_runnable_tag(tag) is False

    @pytest.mark.parametrize(
        "tag",
        [
            "debug-nonroot-165b5d63ce3528e18115acf8191122537154f238",
            "165b5d63ce3528e18115acf8191122537154f238",
        ],
    )
    def test_commit_pinned_duplicates_are_skipped(self, tag):
        assert is_runnable_tag(tag) is False

    @pytest.mark.parametrize(
        "tag", ["latest", "latest-dev", "latest-slim", "next", "nonroot", "debug", "18", "22.1"]
    )
    def test_real_tags_are_kept(self, tag):
        assert is_runnable_tag(tag) is True

    def test_empty_tag_is_rejected(self):
        assert is_runnable_tag("") is False


class TestWwwAuthenticate:
    def test_parses_a_real_cgr_challenge(self):
        header = (
            'Bearer realm="https://cgr.dev/token",service="cgr.dev",'
            'scope="repository:chainguard/node:pull"'
        )
        realm, params = parse_www_authenticate(header)
        assert realm == "https://cgr.dev/token"
        assert params == {"service": "cgr.dev", "scope": "repository:chainguard/node:pull"}

    def test_non_bearer_challenge_yields_nothing(self):
        assert parse_www_authenticate('Basic realm="x"') == ("", {})


class TestRepositoryMapping:
    def test_chainguard_maps_plain_names(self):
        assert ChainguardRepository().repository_for("node") == "chainguard/node"

    def test_distroless_leads_with_the_current_runtime_not_the_legacy_repo(self):
        """`distroless/nodejs` continua publicado e lista as tags 10, 12 e 14.

        Oferecer aquele repositório era responder um pedido de alternativa
        endurecida com um runtime que morreu anos atrás -- uma imagem
        insegura carregando a recomendação desta ferramenta.
        """
        repo = DistrolessRepository()
        assert repo.repository_for("node") == "distroless/nodejs22-debian12"
        assert repo.repository_for("python") == "distroless/python3-debian12"
        assert "distroless/nodejs" not in repo.repositories_for("node")
        assert "distroless/java" not in repo.repositories_for("java")

    def test_java_reaches_the_repositories_that_actually_exist(self):
        """`chainguard/java` responde 403: o repositório não existe. Quem
        digitava `java` recebia zero alternativas endurecidas."""
        assert ChainguardRepository().repositories_for("java") == [
            "chainguard/jdk",
            "chainguard/jre",
        ]
        assert DistrolessRepository().repositories_for("java")[0] == "distroless/java21-debian12"

    def test_build_tools_are_covered_where_they_exist(self):
        assert ChainguardRepository().repository_for("maven") == "chainguard/maven"
        assert ChainguardRepository().repository_for("gradle") == "chainguard/gradle"
        # O Distroless não publica ferramenta de build: maven e gradle rodam
        # no estágio de build, não no de execução. Ausência declarada em vez
        # de mapeada para algo parecido.
        assert DistrolessRepository().repositories_for("maven") == []

    @pytest.mark.parametrize(
        "ref", ["ghcr.io/org/app", "bitnami/node", "node:22-alpine", "", "   "]
    )
    def test_foreign_or_qualified_refs_are_not_claimed(self, ref):
        """`dockerls recommend ghcr.io/org/app` must not fan out to a
        hardened catalogue and offer an unrelated image."""
        assert ChainguardRepository().repository_for(ref) is None
        assert DistrolessRepository().repository_for(ref) is None


CGR_PAYLOAD = {
    "name": "chainguard/node",
    "tags": [
        "latest",
        "latest-dev",
        "next",
        "sha256-0007409db63979837414cf81a13fd24ec7b29fc1f94d316693e2b353e333e938.sig",
    ],
}

GCR_PAYLOAD = {
    "name": "distroless/nodejs",
    "tags": ["latest", "18", "20"],
    "manifest": {
        "sha256:aaa": {
            "tag": ["18"],
            "timeUploadedMs": "1652471368129",
            "imageSizeBytes": "30691518",
        },
        "sha256:bbb": {
            "tag": ["20"],
            "timeUploadedMs": "1752471368129",
            "imageSizeBytes": "27545770",
        },
        "sha256:ccc": {
            "tag": ["latest"],
            "timeUploadedMs": "1752471368129",
            "imageSizeBytes": "0",
        },
    },
}


def _listing(payload):
    return patch(
        "dockerls.integrations.registry.oci.OCIRegistryClient.list_tags",
        AsyncMock(return_value=payload),
    )


class TestChainguardRepository:
    @pytest.mark.asyncio
    async def test_returns_only_runnable_tags_tagged_with_its_source(self):
        with _listing(CGR_PAYLOAD):
            images = await ChainguardRepository().search_tags("node")

        assert [i.tag for i in images] == ["latest", "latest-dev", "next"]
        assert {i.source for i in images} == {"Chainguard"}
        assert images[0].full_reference == "cgr.dev/chainguard/node:latest"

    @pytest.mark.asyncio
    async def test_undated_tags_report_age_as_unknown(self):
        """The OCI listing API returns names only -- claiming a date would
        be an invention, and claiming "old" would unfairly cost score."""
        with _listing(CGR_PAYLOAD):
            images = await ChainguardRepository().search_tags("node")

        assert all(i.age_known is False for i in images)

    @pytest.mark.asyncio
    async def test_unreachable_registry_yields_no_tags(self):
        with _listing(None):
            assert await ChainguardRepository().search_tags("node") == []

    @pytest.mark.asyncio
    async def test_tag_exists_reflects_the_live_listing(self):
        with _listing(CGR_PAYLOAD):
            repo = ChainguardRepository()
            assert await repo.tag_exists("node", "latest") is True
            assert await repo.tag_exists("node", "nope") is False

    @pytest.mark.asyncio
    async def test_tag_exists_is_unknown_when_registry_is_down(self):
        with _listing(None):
            assert await ChainguardRepository().tag_exists("node", "latest") is None


class TestDistrolessRepository:
    @pytest.mark.asyncio
    async def test_gcr_manifest_supplies_dates_and_sizes(self):
        with _listing(GCR_PAYLOAD):
            images = await DistrolessRepository().search_tags("node")

        by_tag = {i.tag: i for i in images}
        assert by_tag["18"].age_known is True
        assert by_tag["18"].size_bytes == 30691518
        assert by_tag["18"].digest == "sha256:aaa"

    @pytest.mark.asyncio
    async def test_newest_first_not_lexical(self):
        """Lexical ordering put nodejs:10 ahead of nodejs:20 -- a security
        tool must not lead with a years-old runtime."""
        with _listing(GCR_PAYLOAD):
            images = await DistrolessRepository().search_tags("node")

        # A consulta agora percorre dois repositórios (nodejs22 e nodejs20),
        # e o duplo `_listing` devolve o mesmo payload para ambos; o que este
        # teste fixa é a ordem dentro de cada listagem.
        versioned = [i.tag for i in images if i.tag not in ("latest", "debug")]
        assert versioned[:2] == ["20", "18"]

    @pytest.mark.asyncio
    async def test_conventional_entrypoints_rank_first(self):
        with _listing(GCR_PAYLOAD):
            images = await DistrolessRepository().search_tags("node")

        assert images[0].tag == "latest"


class TestSourceUrls:
    def test_docker_hub_image_keeps_its_hub_url(self):
        assert source_url("node", "22-alpine").startswith("https://hub.docker.com/_/node")

    def test_chainguard_links_to_its_catalogue(self):
        url = source_url("cgr.dev/chainguard/node", "latest")
        assert url == "https://images.chainguard.dev/directory/image/node/versions"

    def test_distroless_links_to_its_registry_page(self):
        # Igualdade, como no teste do Chainguard logo acima. Duas asserções de
        # substring passariam para uma URL que apontasse para o lugar errado
        # desde que carregasse os dois pedaços em algum canto dela.
        url = source_url("gcr.io/distroless/nodejs", "18")
        assert url == ("https://console.cloud.google.com/gcr/images/distroless/global/nodejs")

    def test_unknown_registry_has_no_url(self):
        assert source_url("ghcr.io/org/app", "v1") == ""
