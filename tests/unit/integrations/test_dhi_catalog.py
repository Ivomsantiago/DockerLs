"""Docker Hardened Images: parsing, discovery, and refusing to be led astray.

Two things are being protected here. The first is correctness of the
declared metadata -- an exclusion (`!gawk`) is not an installed package, and
a `-dev` variant is not the hardened runtime image. The second is the trust
boundary: every path and repository in this integration arrives over the
network, and the tests below feed the parser exactly the shapes a
compromised mirror would produce.
"""

from __future__ import annotations

import json

import httpx
import pytest

from dockerls.domain.value_objects.tristate import Tristate
from dockerls.integrations.dhi.catalog import DHICatalogClient, IndexState
from dockerls.integrations.dhi.definition import DHI_CATALOG, parse_definition
from dockerls.integrations.dhi.repository import DHI, DHIRepository
from dockerls.utils.safe_yaml import safe_load_yaml

# Shaped exactly like image/node/debian-13/22.yaml in the real catalogue.
NODE_RUNTIME = """
name: Node.js 22.x
image: dhi.io/node
variant: runtime
tags:
  - "22"
  - 22.23.2-debian13
platforms:
  - linux/amd64
  - linux/arm64
dates:
  release: "2024-04-24"
  end-of-life: "2027-04-30"
contents:
  packages:
    - '!gawk'
    - '!dpkg'
    - base-files
    - ca-certificates
    - libc6
    - nodejs-22=22.23.2-0
accounts:
  root: true
  run-as: node
os-release:
  id: debian
  version-id: "13"
cmd:
  - node
"""

NODE_DEV = """
name: Node.js 22.x (dev)
image: dhi.io/node
variant: dev
tags:
  - 22-dev
  - 22.23.2-debian13-dev
contents:
  packages:
    - apt
    - bash
    - git
    - nodejs-22=22.23.2-0
accounts:
  run-as: root
os-release:
  id: debian
"""


def _parse(raw: str, url: str = ""):
    return parse_definition(safe_load_yaml(raw), definition_url=url)


class TestDefinitionParsing:
    def test_a_runtime_definition_is_read_faithfully(self):
        declared = _parse(NODE_RUNTIME, url="https://example.invalid/22.yaml")
        assert declared is not None
        assert declared.catalog == DHI_CATALOG
        assert declared.registry_repository == "dhi.io/node"
        assert declared.variant == "runtime"
        assert declared.run_as_user == "node"
        assert declared.end_of_life == "2027-04-30"
        assert declared.os_id == "debian"
        assert declared.os_version == "13"
        assert declared.platforms == ("linux/amd64", "linux/arm64")
        assert declared.cmd == ("node",)
        assert declared.definition_url == "https://example.invalid/22.yaml"

    def test_excluded_packages_are_not_counted_as_installed(self):
        """`!gawk` removes gawk; counting it would invert its meaning."""
        declared = _parse(NODE_RUNTIME)
        assert declared is not None
        assert declared.declared_package_count == 4
        assert declared.package_manager_packages == ()  # `!dpkg` is a removal

    def test_versions_are_stripped_from_package_names(self):
        declared = _parse(NODE_RUNTIME)
        assert declared is not None
        assert declared.declared_package_count == 4

    def test_declared_non_root_is_read_from_run_as(self):
        runtime = _parse(NODE_RUNTIME)
        dev = _parse(NODE_DEV)
        assert runtime is not None and dev is not None
        assert runtime.declared_non_root is Tristate.TRUE
        assert dev.declared_non_root is Tristate.FALSE

    def test_an_unstated_run_as_is_unknown_not_root(self):
        declared = _parse("image: dhi.io/x\ntags: ['1']\n")
        assert declared is not None
        assert declared.declared_non_root is Tristate.UNKNOWN

    def test_presence_proves_but_absence_does_not(self):
        """The asymmetry that keeps a missing package from becoming a claim."""
        dev = _parse(NODE_DEV)
        runtime = _parse(NODE_RUNTIME)
        assert dev is not None and runtime is not None
        assert dev.declared_has_shell is Tristate.TRUE
        assert dev.declared_has_package_manager is Tristate.TRUE
        assert dev.declared_has_debug_tools is Tristate.TRUE
        # The runtime definition names no shell -- which proves nothing.
        assert runtime.declared_has_shell is Tristate.UNKNOWN
        assert runtime.declared_has_package_manager is Tristate.UNKNOWN

    def test_dev_variants_are_identifiable(self):
        dev = _parse(NODE_DEV)
        runtime = _parse(NODE_RUNTIME)
        assert dev is not None and runtime is not None
        assert dev.is_dev_variant is True
        assert runtime.is_dev_variant is False

    @pytest.mark.parametrize(
        "document",
        [
            "just a string",
            "- a\n- list\n",
            "name: no image and no tags\n",
            "",
        ],
    )
    def test_documents_that_are_not_definitions_yield_nothing(self, document):
        assert parse_definition(safe_load_yaml(document)) is None

    def test_structured_values_where_scalars_are_expected_are_dropped(self):
        """A map where a string belongs must not stringify into the model."""
        declared = _parse("image: dhi.io/x\ntags: ['1']\nvariant: {a: 1}\naccounts: [1, 2]\n")
        assert declared is not None
        assert declared.variant == ""
        assert declared.run_as_user == ""


class TestCandidateBuilding:
    async def test_candidates_carry_their_declaration(self, monkeypatch):
        repo = _repository(
            {"debian-13": ["image/node/debian-13/22.yaml"]}, {"22.yaml": NODE_RUNTIME}
        )
        images = await repo.search_tags("node")
        assert len(images) == 1
        image = images[0]
        assert image.name == "dhi.io/node"
        assert image.source == DHI
        assert image.declared is not None
        assert image.declared.run_as_user == "node"

    async def test_the_most_specific_tag_is_chosen(self):
        """`22.23.2-debian13` over `22`: a pinned tag stays meaningful."""
        repo = _repository(
            {"debian-13": ["image/node/debian-13/22.yaml"]}, {"22.yaml": NODE_RUNTIME}
        )
        images = await repo.search_tags("node")
        assert images[0].tag == "22.23.2-debian13"

    async def test_a_definition_publishing_to_another_registry_is_refused(self):
        """Catalogue content must not redirect a scan at an arbitrary host."""
        hostile = NODE_RUNTIME.replace("image: dhi.io/node", "image: evil.example/node")
        repo = _repository({"debian-13": ["image/node/debian-13/22.yaml"]}, {"22.yaml": hostile})
        assert await repo.search_tags("node") == []

    async def test_runtime_definitions_are_read_before_dev_ones(self):
        repo = _repository(
            {"debian-13": ["image/node/debian-13/22-dev.yaml", "image/node/debian-13/22.yaml"]},
            {"22-dev.yaml": NODE_DEV, "22.yaml": NODE_RUNTIME},
        )
        images = await repo.search_tags("node")
        assert images[0].declared is not None
        assert images[0].declared.variant == "runtime"

    @pytest.mark.parametrize(
        "query", ["ghcr.io/org/app", "org/app", "node:22", "", "../etc/passwd"]
    )
    async def test_qualified_or_malformed_queries_are_not_fanned_out(self, query):
        repo = _repository({}, {})
        assert repo.repository_for(query) is None
        assert await repo.search_tags(query) == []

    async def test_tag_existence_is_unknown_rather_than_claimed(self):
        """The catalogue cannot confirm what the registry actually publishes."""
        repo = _repository({}, {})
        assert await repo.tag_exists("node", "22") is None


class TestCatalogIndex:
    async def test_the_tree_is_reduced_to_definition_paths(self, monkeypatch):
        client = _client(
            _transport(
                {
                    "tree": [
                        {"type": "blob", "path": "image/node/debian-13/22.yaml"},
                        {"type": "blob", "path": "image/node/alpine-3.24/22.yaml"},
                        {"type": "blob", "path": "image/node/logo.svg"},
                        {"type": "tree", "path": "image/node"},
                        {"type": "blob", "path": "chart/vault/info.yaml"},
                    ],
                    "sha": "a" * 40,
                }
            )
        )
        variants = await client.variants("node")
        assert set(variants) == {"debian-13", "alpine-3.24"}
        assert client.revision == "a" * 40

    @pytest.mark.parametrize(
        "path",
        [
            "image/../../../etc/passwd",
            "image/node/../../secrets.yaml",
            "/etc/shadow",
            "image/node/debian-13/22.exe",
            "image/NODE/debian-13/22.yaml",
        ],
    )
    async def test_unexpected_paths_never_enter_the_index(self, path):
        client = _client(_transport({"tree": [{"type": "blob", "path": path}], "sha": "b" * 40}))
        assert await client.variants("node") == {}

    async def test_a_definition_at_an_unexpected_path_is_never_fetched(self):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, text=NODE_RUNTIME)

        client = _client(httpx.MockTransport(handler))
        assert await client.definition("../../../etc/passwd") is None
        assert await client.definition("image/node/debian-13/../../../x.yaml") is None
        assert calls == []

    async def test_a_query_that_is_not_a_catalogue_name_makes_no_request(self):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(200, json={"tree": [], "sha": ""})

        client = _client(httpx.MockTransport(handler))
        assert await client.variants("../etc") == {}
        assert await client.variants("node:22") == {}
        assert calls == []

    async def test_a_rate_limited_api_yields_no_candidates_rather_than_an_error(self):
        client = _client(httpx.MockTransport(lambda request: httpx.Response(403, text="limit")))
        assert await client.variants("node") == {}

    async def test_an_unparseable_tree_yields_no_candidates(self):
        client = _client(httpx.MockTransport(lambda request: httpx.Response(200, text="not json")))
        assert await client.variants("node") == {}

    async def test_an_oversized_response_is_discarded(self):
        body = "x" * (33 * 1024 * 1024)
        client = _client(httpx.MockTransport(lambda request: httpx.Response(200, text=body)))
        assert await client.variants("node") == {}

    async def test_a_tampered_cached_index_is_rejected_wholesale(self):
        """A cache file another process can write is re-validated on read."""
        cache = _FakeCache(
            {
                "dhi:index": {
                    "index": {"node": {"d": ["image/node/d/../../../etc/x.yaml"]}},
                    "revision": "z",
                }
            }
        )
        client = DHICatalogClient(cache=cache, ttl_seconds=60)
        client._client = httpx.AsyncClient(  # noqa: SLF001 - injecting the transport
            transport=httpx.MockTransport(lambda request: httpx.Response(404))
        )
        assert await client.variants("node") == {}

    async def test_a_valid_cached_index_avoids_the_network_entirely(self):
        calls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(str(request.url))
            return httpx.Response(500)

        cache = _FakeCache(
            {
                "dhi:index": {
                    "index": {"node": {"debian-13": ["image/node/debian-13/22.yaml"]}},
                    "revision": "c" * 40,
                }
            }
        )
        client = DHICatalogClient(cache=cache, ttl_seconds=60)
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))  # noqa: SLF001
        assert await client.variants("node") == {"debian-13": ["image/node/debian-13/22.yaml"]}
        assert calls == []


class TestAnEmptyAnswerSaysWhichKindOfEmpty:
    """`variants()` returns `{}` for three different things, and only one of
    them is about the image: the catalogue has no such image, the catalogue
    could not be read, and GitHub truncated the tree.

    A caller that cannot tell them apart reports "DHI publishes no hardened
    build of this" when what actually happened was that nobody asked -- an
    unreachable catalogue turned into a finding about the image. The empty
    dict is still what comes back (discovery degrades, it does not fail);
    what is fixed is that the reason survives it.
    """

    async def test_a_complete_catalogue_makes_an_empty_answer_conclusive(self):
        client = _client(
            _transport(
                {"tree": [{"type": "blob", "path": "image/node/d/22.yaml"}], "sha": "a" * 40}
            )
        )

        assert await client.variants("ruby") == {}
        assert client.index_state is IndexState.COMPLETE
        assert client.index_state.is_conclusive

    @pytest.mark.parametrize(
        "response",
        [
            httpx.Response(403, text="rate limited"),
            httpx.Response(500, text="server error"),
            httpx.Response(200, text="not json"),
        ],
    )
    async def test_an_unreadable_catalogue_is_unavailable_not_empty(self, response):
        client = _client(httpx.MockTransport(lambda request: response))

        assert await client.variants("node") == {}
        assert client.index_state is IndexState.UNAVAILABLE
        assert not client.index_state.is_conclusive

    async def test_a_network_error_is_unavailable_too(self):
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host")

        client = _client(httpx.MockTransport(boom))

        assert await client.variants("node") == {}
        assert client.index_state is IndexState.UNAVAILABLE

    async def test_a_truncated_tree_is_not_a_complete_catalogue(self):
        """GitHub truncates very large trees. The index it produces is real
        and short: an image it does not name may still exist."""
        client = _client(
            _transport(
                {
                    "tree": [{"type": "blob", "path": "image/node/debian-13/22.yaml"}],
                    "sha": "a" * 40,
                    "truncated": True,
                }
            )
        )

        assert set(await client.variants("node")) == {"debian-13"}
        assert client.index_state is IndexState.TRUNCATED
        assert not client.index_state.is_conclusive

    async def test_before_any_query_the_index_is_not_loaded(self):
        client = _client(_transport({"tree": [], "sha": ""}))

        assert client.index_state is IndexState.NOT_LOADED

    async def test_the_repository_still_degrades_and_can_tell_why(self):
        """`DHIRepository` returns no candidates either way -- discovery
        degrades rather than failing the run. What changed is that the
        reason is still readable afterwards instead of being flattened into
        an empty list."""
        unreachable = _client(httpx.MockTransport(lambda request: httpx.Response(503)))
        assert await DHIRepository(catalog=unreachable).search_tags("node") == []
        assert unreachable.index_state is IndexState.UNAVAILABLE

        present = _client(
            _transport({"tree": [{"type": "blob", "path": "image/go/d/1.yaml"}], "sha": "a" * 40})
        )
        assert await DHIRepository(catalog=present).search_tags("node") == []
        assert present.index_state is IndexState.COMPLETE


# --------------------------------------------------------------------------
# Doubles
# --------------------------------------------------------------------------


class _FakeCache:
    def __init__(self, seed: dict | None = None):
        self.data = dict(seed or {})

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value, ttl_seconds=86400):
        self.data[key] = value

    async def delete(self, key):
        self.data.pop(key, None)

    async def clear(self):
        self.data.clear()


def _transport(tree_payload: dict) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        # Igualdade, não `in`: `evil-api.github.com.attacker.test` contém
        # "api.github.com" como substring e não é o GitHub. Num duplo de teste
        # a diferença não é explorável, mas é o mesmo padrão que seria um bug
        # de verdade em código de produção -- e um padrão que passa na revisão
        # aqui reaparece lá.
        if request.url.host == "api.github.com":
            return httpx.Response(200, text=json.dumps(tree_payload))
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def _client(transport: httpx.MockTransport) -> DHICatalogClient:
    client = DHICatalogClient(cache=None, ttl_seconds=60)
    client._client = httpx.AsyncClient(transport=transport)  # noqa: SLF001 - test injection
    return client


class _StubCatalog:
    """Answers from in-memory definitions, so no test touches the network."""

    def __init__(self, variants: dict[str, list[str]], bodies: dict[str, str]):
        self._variants = variants
        self._bodies = bodies
        self.revision = "test"

    async def variants(self, image: str) -> dict[str, list[str]]:
        return dict(self._variants) if image == "node" else {}

    async def definition(self, path: str):
        body = self._bodies.get(path.rsplit("/", 1)[-1])
        if body is None:
            return None
        return parse_definition(safe_load_yaml(body), definition_url=f"https://example/{path}")

    async def close(self) -> None:
        return None


def _repository(variants: dict[str, list[str]], bodies: dict[str, str]) -> DHIRepository:
    return DHIRepository(catalog=_StubCatalog(variants, bodies))  # type: ignore[arg-type]
