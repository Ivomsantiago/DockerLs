"""Where DockerLs is allowed to send a request, and why that needs a policy.

An image reference is user input, and it carries a hostname. `dockerls
analyze 169.254.169.254/latest` is a well-formed reference, and resolving it
means issuing `GET https://169.254.169.254/v2/latest/manifests/...` -- the
cloud metadata endpoint. On a CI runner, a reference arriving from a pull
request, a config file or an environment variable therefore turns this tool
into an SSRF primitive against the host's internal network. The response body
never reaches the requester, but the *reach* does, and blind is still SSRF.

The naive fix -- refuse every private address -- is wrong here, and the
project brief says so explicitly: internal registries on RFC1918 addresses
are ordinary, legitimate infrastructure, and a scanner that cannot look at
`registry.internal:5000` is a scanner nobody can use. So the policy
distinguishes two things that get lumped together:

* **loopback and link-local** are refused by default. No legitimate registry
  is reachable at `127.0.0.1` *from the perspective of a reference someone
  else supplied*, and `169.254.0.0/16` is where every cloud provider parks
  its credential endpoint. This is the actual attack.
* **private ranges** (RFC1918, unique-local) are allowed by default, because
  that is where real internal registries live -- and tightened with a single
  setting when a deployment wants to.

Either default can be overridden, and an explicit host allowlist wins over
both: an operator who genuinely runs a registry on localhost says so once.

Hostnames are judged by where they *resolve*, not by how they are spelled:
`localhost` and an attacker-controlled name whose A record points at
127.0.0.1 are the same request, and only one of them looks suspicious in a
config file. Resolving a name is I/O, so it does not happen here -- this
module decides over addresses it is handed, and
`infrastructure/network/host_guard.py` is what performs the lookup. That
split is what keeps the rule testable without a network and the domain free
of sockets.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import StrEnum


class NetworkDecision(StrEnum):
    """Why a host was allowed or refused. Reported, never silent."""

    ALLOWED = "ALLOWED"
    ALLOWED_BY_ALLOWLIST = "ALLOWED_BY_ALLOWLIST"
    BLOCKED_LOOPBACK = "BLOCKED_LOOPBACK"
    BLOCKED_LINK_LOCAL = "BLOCKED_LINK_LOCAL"
    BLOCKED_PRIVATE = "BLOCKED_PRIVATE"
    BLOCKED_UNSPECIFIED = "BLOCKED_UNSPECIFIED"
    BLOCKED_UNRESOLVABLE = "BLOCKED_UNRESOLVABLE"
    BLOCKED_SPECIAL = "BLOCKED_SPECIAL"
    BLOCKED_SCHEME = "BLOCKED_SCHEME"


#: Decisions that permit the request.
_ALLOWING = (NetworkDecision.ALLOWED, NetworkDecision.ALLOWED_BY_ALLOWLIST)


@dataclass(frozen=True)
class NetworkPolicy:
    """What a reference is permitted to make this process talk to."""

    #: RFC1918 / unique-local. Default True: internal registries are normal.
    allow_private_networks: bool = True
    #: 127.0.0.0/8, ::1. Default False -- this is the SSRF case, and a
    #: registry on localhost is a deliberate, local choice that deserves to
    #: be stated.
    allow_loopback: bool = False
    #: 169.254.0.0/16, fe80::/10. Default False: cloud metadata lives here
    #: and nothing else legitimate does.
    allow_link_local: bool = False
    #: Hosts permitted regardless of where they resolve, exactly as written
    #: in the reference (host or host:port).
    allowed_hosts: frozenset[str] = field(default_factory=frozenset)

    def is_allowlisted(self, host: str) -> bool:
        """Whether `host` is permitted outright, before any lookup.

        Checked first by the caller so an operator who deliberately runs a
        registry on localhost is never subjected to a DNS round-trip to be
        told what they already declared.
        """
        candidates = {host.strip().lower(), hostname_of(host).lower()}
        return bool(candidates & {entry.strip().lower() for entry in self.allowed_hosts})

    def decide_addresses(
        self, addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address]
    ) -> NetworkDecision:
        """Classify a host from the addresses it resolves to.

        **Every** address must pass. A name answering with one public and
        one loopback address is the shape of a DNS-rebinding attack, and the
        connection would be free to use either.
        """
        if not addresses:
            # A name that resolves to nothing cannot be reached anyway;
            # refusing here keeps the failure on the policy's terms rather
            # than as a connection error deep inside an HTTP client.
            return NetworkDecision.BLOCKED_UNRESOLVABLE
        for address in addresses:
            decision = self._classify(address)
            if decision not in _ALLOWING:
                return decision
        return NetworkDecision.ALLOWED

    def explain(self, host: str, decision: NetworkDecision) -> str:
        """A refusal a reader can act on, naming the setting that changes it."""
        return _EXPLANATIONS.get(decision, "").format(host=host)

    def _classify(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> NetworkDecision:
        # An IPv6 address may *carry* an IPv4 one. `::ffff:127.0.0.1`,
        # `2002:7f00:1::` (6to4) and `64:ff9b::7f00:1` (NAT64) all reach
        # 127.0.0.1 on a host with the matching translation configured, and
        # only the first of the three is recognised by `is_loopback`. Judge
        # the address that would actually be contacted, then fall through to
        # judging the wrapper too -- a tunnel does not launder a destination.
        embedded = _embedded_ipv4(address)
        if embedded is not None:
            decision = self._classify(embedded)
            if decision not in _ALLOWING:
                return decision

        if address.is_unspecified or _in_any(address, _WILDCARD_SOURCE):
            # 0.0.0.0/8 in full, not just the exact 0.0.0.0: Linux routes
            # `0.x.y.z` to the local host, so the whole block is a spelling
            # of "loopback" that `is_loopback` does not catch.
            return NetworkDecision.BLOCKED_UNSPECIFIED
        if address.is_loopback:
            return (
                NetworkDecision.ALLOWED if self.allow_loopback else NetworkDecision.BLOCKED_LOOPBACK
            )
        if address.is_link_local:
            return (
                NetworkDecision.ALLOWED
                if self.allow_link_local
                else NetworkDecision.BLOCKED_LINK_LOCAL
            )
        if _in_any(address, _SPECIAL) or address.is_multicast or address.is_reserved:
            # Shared/benchmark/reserved space and the carrier-grade NAT block
            # where Alibaba Cloud serves instance credentials
            # (100.100.100.200). None of it hosts a registry, all of it is
            # reachable from a CI runner, so it is refused outright rather
            # than folded into `allow_private_networks` -- an operator who
            # turns private networks on to reach 10.0.0.0/8 has not thereby
            # asked for a route to a metadata service.
            return NetworkDecision.BLOCKED_SPECIAL
        if address.is_private:
            return (
                NetworkDecision.ALLOWED
                if self.allow_private_networks
                else NetworkDecision.BLOCKED_PRIVATE
            )
        return NetworkDecision.ALLOWED


#: 0.0.0.0/8. `is_unspecified` is only true for the single address 0.0.0.0,
#: but the whole block behaves as "this host" on Linux.
_WILDCARD_SOURCE = (ipaddress.ip_network("0.0.0.0/8"),)

#: Ranges that are neither public nor plausible registry homes. Enumerated
#: rather than derived from `is_global`, whose membership has changed between
#: Python releases -- a security boundary should not move with the runtime.
_SPECIAL = (
    ipaddress.ip_network("100.64.0.0/10"),  # RFC 6598 CGNAT; Alibaba metadata
    ipaddress.ip_network("192.0.0.0/24"),  # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),  # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),  # deprecated 6to4 relay anycast
    ipaddress.ip_network("198.18.0.0/15"),  # benchmarking
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3
    ipaddress.ip_network("240.0.0.0/4"),  # reserved, incl. 255.255.255.255
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64
    ipaddress.ip_network("64:ff9b:1::/48"),  # local-use NAT64
    ipaddress.ip_network("100::/64"),  # discard-only
    ipaddress.ip_network("2001:db8::/32"),  # documentation
)

#: 6to4 (RFC 3056) and Teredo (RFC 4380) prefixes, whose payload is an IPv4
#: address that the host may actually route to.
_SIXTOFOUR = ipaddress.ip_network("2002::/16")
_TEREDO = ipaddress.ip_network("2001::/32")
_NAT64 = ipaddress.ip_network("64:ff9b::/96")


def _in_any(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...],
) -> bool:
    return any(address.version == net.version and address in net for net in networks)


def _embedded_ipv4(
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """The IPv4 address an IPv6 address encodes, if it encodes one.

    Covers the four encodings a host can be configured to translate:
    IPv4-mapped and IPv4-compatible (`::ffff:a.b.c.d`, `::a.b.c.d`), 6to4,
    Teredo and NAT64. Returns None for an ordinary IPv6 address.
    """
    if not isinstance(address, ipaddress.IPv6Address):
        return None
    if address.ipv4_mapped is not None:
        return address.ipv4_mapped
    if address.sixtofour is not None and address in _SIXTOFOUR:
        return address.sixtofour
    if address.teredo is not None and address in _TEREDO:
        # (server, client); the client is the address packets reach.
        return address.teredo[1]
    if address in _NAT64:
        return ipaddress.IPv4Address(int(address) & 0xFFFFFFFF)
    return None


_EXPLANATIONS = {
    NetworkDecision.BLOCKED_LOOPBACK: (
        "{host} resolves to a loopback address. Refused by default: a reference that "
        "reaches localhost is how an untrusted image name becomes a request to a "
        "service on this machine. Set network_allow_loopback = true, or add the host "
        "to network_allowed_hosts, if this is deliberate."
    ),
    NetworkDecision.BLOCKED_LINK_LOCAL: (
        "{host} resolves to a link-local address (169.254.0.0/16). Refused by default: "
        "this is where cloud providers serve instance credentials. Set "
        "network_allow_link_local = true only if you know why you need it."
    ),
    NetworkDecision.BLOCKED_PRIVATE: (
        "{host} resolves to a private address and network_allow_private_networks is "
        "off. Turn it on, or add the host to network_allowed_hosts."
    ),
    NetworkDecision.BLOCKED_UNSPECIFIED: (
        "{host} resolves to an unspecified address (0.0.0.0/8 or ::), which names this "
        "host rather than a registry."
    ),
    NetworkDecision.BLOCKED_UNRESOLVABLE: "{host} could not be resolved to any address.",
    NetworkDecision.BLOCKED_SPECIAL: (
        "{host} resolves into reserved, shared or carrier-grade-NAT space (for example "
        "100.64.0.0/10, where some clouds serve instance credentials). No registry is "
        "published there; add the host to network_allowed_hosts if this is deliberate."
    ),
    NetworkDecision.BLOCKED_SCHEME: (
        "{host} was requested over a scheme other than http/https, which this tool "
        "never follows."
    ),
}


def hostname_of(host: str) -> str:
    """Strip an optional `:port`, leaving the name or literal address.

    IPv6 literals in a registry reference are bracketed (`[::1]:5000`), so
    the bracket form is handled before the naive rsplit that would otherwise
    cut a bare `::1` in half.
    """
    value = host.strip()
    if not value:
        return ""
    if value.startswith("["):
        closing = value.find("]")
        return value[1:closing] if closing > 1 else ""
    if value.count(":") == 1:
        return value.rsplit(":", 1)[0]
    return value
