"""Every hop is a decision, not just the first one.

The policy used to be applied to the hostname in the reference and nowhere
else. Two things chosen by the far end happen after that check, and both
issue a request:

* a `302 Location:` the client follows, because `follow_redirects=True`;
* the `realm` in a `WWW-Authenticate` challenge, which the OCI token dance
  fetches by definition.

A registry that is reachable but hostile -- or a proxy, a cache, or a
compromised mirror on the path to an honest one -- therefore picked the
destination of a request issued from inside the CI runner. That is the same
SSRF the policy exists to prevent, arriving one hop later.

These tests use a `MockTransport`, so nothing here touches the network: the
question is whether the request is *attempted*, and the transport is where
that becomes observable.
"""

from __future__ import annotations

import ipaddress

import httpx
import pytest

from dockerls.domain.value_objects.network_policy import (
    NetworkDecision,
    NetworkPolicy,
)
from dockerls.infrastructure.network.guarded_client import (
    BlockedRequestError,
    guarded_async_client,
)
from dockerls.infrastructure.network.host_guard import HostGuard
from dockerls.integrations.registry.oci import OCIRegistryClient, is_fetchable_realm


def _addresses(*values: str) -> list:
    return [ipaddress.ip_address(v) for v in values]


class _FixedResolutionGuard(HostGuard):
    """A guard with the DNS replaced by a table.

    Rebinding and metadata names are the point of these tests and neither
    can be reproduced against real DNS from a test runner.
    """

    def __init__(self, table: dict[str, list[str]], policy: NetworkPolicy | None = None):
        super().__init__(policy)
        self._table = table

    def decide(self, host: str) -> NetworkDecision:
        if self._policy.is_allowlisted(host):
            return NetworkDecision.ALLOWED_BY_ALLOWLIST
        from dockerls.domain.value_objects.network_policy import hostname_of

        name = hostname_of(host)
        answers = self._table.get(name)
        if answers is None:
            return NetworkDecision.BLOCKED_UNRESOLVABLE
        return self._policy.decide_addresses(_addresses(*answers))


PUBLIC = "203.0.113.10"  # only used as a *name*; never resolved as a literal


class TestAddressClassification:
    """Encodings of a forbidden address are the forbidden address."""

    @pytest.mark.parametrize(
        ("address", "expected"),
        [
            # 0.0.0.0/8 in full. `is_unspecified` only catches the exact
            # 0.0.0.0, and Linux routes the rest of the block to this host.
            ("0.1.2.3", NetworkDecision.BLOCKED_UNSPECIFIED),
            ("0.0.0.1", NetworkDecision.BLOCKED_UNSPECIFIED),
            # IPv4-mapped IPv6.
            ("::ffff:127.0.0.1", NetworkDecision.BLOCKED_LOOPBACK),
            ("::ffff:169.254.169.254", NetworkDecision.BLOCKED_LINK_LOCAL),
            # 6to4 and NAT64 both carry an IPv4 destination the host may
            # translate; neither is recognised by `is_loopback`.
            ("2002:7f00:1::", NetworkDecision.BLOCKED_LOOPBACK),
            ("64:ff9b::7f00:1", NetworkDecision.BLOCKED_LOOPBACK),
            ("2002:a9fe:a9fe::", NetworkDecision.BLOCKED_LINK_LOCAL),
            # Carrier-grade NAT: where Alibaba Cloud serves instance
            # credentials (100.100.100.200).
            ("100.100.100.200", NetworkDecision.BLOCKED_SPECIAL),
            ("240.0.0.1", NetworkDecision.BLOCKED_SPECIAL),
            ("224.0.0.1", NetworkDecision.BLOCKED_SPECIAL),
            ("198.18.0.1", NetworkDecision.BLOCKED_SPECIAL),
        ],
    )
    def test_encoded_forbidden_addresses_are_still_forbidden(self, address, expected):
        assert NetworkPolicy().decide_addresses(_addresses(address)) is expected

    @pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700::1", "::ffff:10.0.0.5"])
    def test_ordinary_destinations_are_unaffected(self, address):
        """Including an IPv4-mapped *private* address: unwrapping must not
        turn a legitimate internal registry into a refusal."""
        assert NetworkPolicy().decide_addresses(_addresses(address)) is NetworkDecision.ALLOWED

    def test_the_special_refusal_names_a_way_out(self):
        policy = NetworkPolicy()
        message = policy.explain("metadata.internal", NetworkDecision.BLOCKED_SPECIAL)
        assert "network_allowed_hosts" in message


class TestRedirectHops:
    async def test_a_redirect_into_the_metadata_range_is_refused(self):
        guard = _FixedResolutionGuard(
            {"registry.example": ["93.184.216.34"], "metadata.google.internal": ["169.254.169.254"]}
        )
        reached: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            reached.append(str(request.url))
            if request.url.host == "registry.example":
                return httpx.Response(
                    302, headers={"Location": "http://metadata.google.internal/computeMetadata/v1/"}
                )
            return httpx.Response(200, json={"token": "leaked"})

        async with guarded_async_client(
            guard, transport=httpx.MockTransport(handler), follow_redirects=True
        ) as client:
            with pytest.raises(BlockedRequestError):
                await client.get("https://registry.example/v2/")

        assert reached == ["https://registry.example/v2/"], (
            "the redirect target must never reach the transport"
        )

    async def test_a_redirect_chain_ending_public_is_still_followed(self):
        guard = _FixedResolutionGuard(
            {"registry.example": ["93.184.216.34"], "cdn.example": ["93.184.216.35"]}
        )

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.host == "registry.example":
                return httpx.Response(302, headers={"Location": "https://cdn.example/blob"})
            return httpx.Response(200, json={"ok": True})

        async with guarded_async_client(
            guard, transport=httpx.MockTransport(handler), follow_redirects=True
        ) as client:
            resp = await client.get("https://registry.example/v2/")
        assert resp.json() == {"ok": True}

    async def test_a_non_http_hop_is_refused_by_scheme(self):
        guard = _FixedResolutionGuard({"registry.example": ["93.184.216.34"]})

        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
            raise AssertionError(f"transport must not see {request.url}")

        async with guarded_async_client(
            guard, transport=httpx.MockTransport(handler), follow_redirects=True
        ) as client:
            with pytest.raises(BlockedRequestError) as caught:
                await client.get("file:///etc/passwd")
        assert "scheme" in str(caught.value)
        assert "/etc/passwd" not in str(caught.value), "the refused URL must not be echoed back"

    async def test_the_first_hop_is_checked_too(self):
        guard = _FixedResolutionGuard({"evil.example": ["169.254.169.254"]})

        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - never reached
            raise AssertionError(f"transport must not see {request.url}")

        async with guarded_async_client(guard, transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(BlockedRequestError):
                await client.get("https://evil.example/v2/")

    async def test_a_blocked_hop_reads_as_an_http_error_to_existing_callers(self):
        """Every integration in this codebase already treats `httpx.HTTPError`
        as "could not determine". A refusal must land in that handler rather
        than escaping as a crash -- an unknown is a worse answer than a
        result, but a traceback is worse than both."""
        assert issubclass(BlockedRequestError, httpx.HTTPError)


class TestTokenRealm:
    """`WWW-Authenticate: Bearer realm="..."` is a remote party naming a URL
    this process will fetch."""

    @pytest.mark.parametrize(
        "realm",
        [
            "file:///etc/passwd",
            "gopher://127.0.0.1:6379/_INFO",
            "/relative/token",
            "",
            "not a url at all",
            "https://",
        ],
    )
    def test_realms_that_are_not_http_urls_are_refused(self, realm):
        assert is_fetchable_realm(realm) is False

    @pytest.mark.parametrize(
        "realm",
        ["https://auth.docker.io/token", "http://registry.internal:5000/auth"],
    )
    def test_ordinary_realms_are_accepted(self, realm):
        assert is_fetchable_realm(realm) is True

    async def test_a_hostile_realm_is_never_fetched(self):
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Bearer realm="file:///etc/passwd",service="x"'},
            )

        client = OCIRegistryClient("registry.example")
        client._client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            assert await client.list_tags("library/alpine") is None
        finally:
            await client.close()
        assert seen == ["https://registry.example/v2/library/alpine/tags/list?n=1000"]

    async def test_a_realm_pointing_at_the_metadata_service_is_blocked_by_the_guard(self):
        guard = _FixedResolutionGuard(
            {"registry.example": ["93.184.216.34"], "metadata.example": ["169.254.169.254"]}
        )
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.host)
            return httpx.Response(
                401,
                headers={"WWW-Authenticate": 'Bearer realm="https://metadata.example/token"'},
            )

        client = OCIRegistryClient("registry.example", guard=guard)
        client._client = guarded_async_client(guard, transport=httpx.MockTransport(handler))
        try:
            # The refusal is an HTTPError, which `_fetch_tags` already reads
            # as "could not be reached" -- so the caller gets None, not a
            # traceback and not an empty tag list pretending to be an answer.
            assert await client.list_tags("library/alpine") is None
        finally:
            await client.close()
        assert seen == ["registry.example"]
