"""Branch coverage for `HostGuard`/`_resolve`, the SSRF gate.

This is the piece that decides whether an image reference is allowed to
make this process connect anywhere -- documented as ALTA risk in the
project's own AUDIT.md (F4/F14) -- so the DNS-failure and malformed-answer
paths get the same attention as the address-classification rules already
covered in `tests/adversarial/test_network_and_output.py`.
"""

from __future__ import annotations

import socket

import pytest

from dockerls.domain.value_objects.network_policy import NetworkDecision, NetworkPolicy
from dockerls.infrastructure.network.host_guard import HostGuard, _resolve, host_of_url


class TestPolicyProperty:
    def test_exposes_the_policy_it_was_built_with(self):
        policy = NetworkPolicy(allow_private_networks=False)
        guard = HostGuard(policy)
        assert guard.policy is policy

    def test_defaults_to_a_policy_when_none_is_given(self):
        guard = HostGuard()
        assert isinstance(guard.policy, NetworkPolicy)


class TestHostOfUrl:
    def test_a_bare_host_with_no_scheme_is_returned_as_is(self):
        """`urlsplit` finds no `netloc` when there is no `//` -- a plain
        `registry.internal:5000` never had a scheme to strip in the first
        place, so it passes through unchanged rather than being read as
        `BLOCKED_UNRESOLVABLE` for looking like a path."""
        assert host_of_url("registry.internal:5000") == "registry.internal:5000"

    def test_strips_surrounding_whitespace_on_a_bare_host(self):
        assert host_of_url("  gitlab.com  ") == "gitlab.com"

    def test_extracts_the_host_from_a_full_url(self):
        assert host_of_url("https://gitlab.com/exploit-database/exploitdb") == "gitlab.com"

    def test_credentials_embedded_in_the_url_are_not_read_as_the_host(self):
        assert host_of_url("https://user:pass@registry.internal:5000/v2/") == (
            "registry.internal:5000"
        )


class TestResolveFailure:
    """`_resolve` degrades to an empty list -- read by the policy as
    unresolvable, and therefore refused -- rather than raising or
    propagating a DNS error."""

    def test_a_lookup_error_returns_no_addresses(self, monkeypatch):
        def raise_oserror(*args, **kwargs):
            raise OSError("nodename nor servname provided, or not known")

        monkeypatch.setattr(socket, "getaddrinfo", raise_oserror)

        assert _resolve("this-name-does-not-resolve.invalid") == []

    def test_a_hostname_socket_cannot_encode_returns_no_addresses(self, monkeypatch):
        def raise_unicode_error(*args, **kwargs):
            raise UnicodeError("encoding with 'idna' codec failed")

        monkeypatch.setattr(socket, "getaddrinfo", raise_unicode_error)

        assert _resolve("xn--\udfff-bad-label") == []

    def test_a_lookup_failure_is_refused_end_to_end(self, monkeypatch):
        monkeypatch.setattr(
            socket, "getaddrinfo", lambda *a, **k: (_ for _ in ()).throw(OSError("boom"))
        )

        guard = HostGuard()
        assert guard.allows("this-name-does-not-resolve.invalid") is False
        assert guard.decide("this-name-does-not-resolve.invalid") is (
            NetworkDecision.BLOCKED_UNRESOLVABLE
        )


class TestResolveMalformedAnswers:
    """A `getaddrinfo` entry that does not parse as an address is skipped,
    not fatal -- one broken record must not take down every other, valid
    answer for the same name."""

    def test_an_unparseable_sockaddr_is_skipped(self, monkeypatch):
        # (family, type, proto, canonname, sockaddr) -- a well-formed tuple
        # whose address slot is garbage, mixed with a good one.
        good = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        bad = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 0))
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [bad, good])

        addresses = _resolve("example.com")

        assert [str(a) for a in addresses] == ["93.184.216.34"]

    def test_a_sockaddr_missing_the_address_slot_is_skipped(self, monkeypatch):
        # An empty sockaddr triggers IndexError on `info[4][0]`.
        malformed = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ())
        good = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [malformed, good])

        addresses = _resolve("example.com")

        assert [str(a) for a in addresses] == ["93.184.216.34"]

    def test_every_answer_unparseable_is_the_same_as_no_answer(self, monkeypatch):
        bad = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("not-an-ip", 0))
        monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: [bad])

        assert _resolve("example.com") == []


class TestResolveLiterals:
    """An address literal never touches the network -- covered indirectly
    elsewhere via `HostGuard`, pinned here directly against `_resolve`."""

    @pytest.mark.parametrize("literal", ["127.0.0.1", "::1", "169.254.169.254"])
    def test_an_ip_literal_short_circuits_dns(self, literal, monkeypatch):
        def fail_if_called(*args, **kwargs):
            raise AssertionError("a literal must not reach socket.getaddrinfo")

        monkeypatch.setattr(socket, "getaddrinfo", fail_if_called)

        assert [str(a) for a in _resolve(literal)] == [literal]
