"""Apply the network policy to *every* request, not just the first one.

Checking the host of a reference before opening a client is necessary and
not sufficient. Two things happen after that check that can move the
request somewhere else entirely, and both are controlled by the far end:

* **Redirects.** `follow_redirects=True` means a registry answering `302
  Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  gets that request issued from inside the client, with the guard's verdict
  on the *original* host still standing. The reference looked innocuous
  because it was; the destination was chosen afterwards.
* **`WWW-Authenticate`.** The OCI token dance takes the URL to authenticate
  against from a header the registry sends back (`Bearer realm="..."`). That
  is a remote party naming a URL this process will then fetch. It is the
  same primitive as an open redirect, arriving through a different door.

An `httpx` request event hook fires once per hop -- the initial request and
every redirect -- which is exactly the granularity the policy needs. Raising
from the hook aborts the transfer before the socket for that hop is opened.

The scheme is checked in the same place. `Location: file:///etc/shadow` and
`Location: gopher://...` are not requests this tool has any reason to make,
and an allowlist of `http`/`https` is cheaper to reason about than an
exhaustive list of what to refuse.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import httpx
from loguru import logger

if TYPE_CHECKING:
    from collections.abc import Callable, Coroutine
    from typing import Any

    from dockerls.infrastructure.network.host_guard import HostGuard

#: The only schemes a hop may use. Anything else is refused by name.
ALLOWED_SCHEMES = frozenset({"http", "https"})


class BlockedRequestError(httpx.HTTPError):
    """A hop the network policy refused.

    Derived from `httpx.HTTPError` deliberately: every caller in this
    codebase already treats an `HTTPError` as "could not determine", which
    is the correct reading of a refused request. A new exception type would
    have escaped those handlers and turned a policy decision into a crash --
    and a crash is a worse answer than an explicit unknown.
    """

    def __init__(self, url: httpx.URL, reason: str):
        self.url = url
        self.reason = reason
        super().__init__(reason)


def guard_request(guard: HostGuard, request: httpx.Request) -> None:
    """Raise `BlockedRequestError` unless `request` is within policy."""
    url = request.url
    if url.scheme not in ALLOWED_SCHEMES:
        # httpx normalises an unsupported scheme to the empty string, so the
        # message names what it required rather than what it got -- and the
        # URL itself is never echoed, because a token can live in its query.
        raise BlockedRequestError(
            url,
            f"Refusing a request whose scheme is not one of "
            f"{'/'.join(sorted(ALLOWED_SCHEMES))} (got {url.scheme or 'none'}).",
        )
    # `url.netloc` carries any userinfo; `host` and `port` do not, and the
    # guard must judge the name that will actually be resolved.
    host = url.host if url.port is None else f"{url.host}:{url.port}"
    if not host:
        raise BlockedRequestError(url, "Refusing a request with no host.")
    if not guard.allows(host):
        raise BlockedRequestError(url, guard.explain(host))


def request_hook(guard: HostGuard) -> Callable[[httpx.Request], Coroutine[Any, Any, None]]:
    """An `httpx` async request event hook enforcing `guard` on every hop."""

    async def _hook(request: httpx.Request) -> None:
        try:
            guard_request(guard, request)
        except BlockedRequestError as e:
            logger.warning(f"Blocked request to {e.url.host}: {e.reason}")
            raise

    return _hook


def guarded_async_client(guard: HostGuard | None, **kwargs: Any) -> httpx.AsyncClient:
    """An `httpx.AsyncClient` whose every hop is checked against `guard`.

    A `None` guard builds an ordinary client: the callers that reach fixed,
    vendor-owned endpoints (and are constructed in places with no guard to
    hand) keep working unchanged rather than silently losing their network.
    Those callers pass `follow_redirects=False`, so there is no second hop
    to police in the first place.
    """
    if guard is None:
        return httpx.AsyncClient(**kwargs)
    hooks = dict(kwargs.pop("event_hooks", None) or {})
    hooks["request"] = [*hooks.get("request", []), request_hook(guard)]
    return httpx.AsyncClient(event_hooks=hooks, **kwargs)
