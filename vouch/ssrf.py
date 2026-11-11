"""
SSRF protection for outbound fetches (did:web resolution, revocation lists,
status lists).

A verifier fetches URLs derived from attacker-controlled input (an issuer DID,
a credentialStatus entry). Without a guard, an attacker can point those at
internal services or the cloud metadata endpoint (169.254.169.254). This module
validates that a URL is https and resolves only to public, routable addresses.
Callers that use their own HTTP client disable redirects so a public host cannot
302 to an internal one; `fetch_bytes` and `fetch_json` follow redirects
themselves, validate every hop, pin the connection to the validated address, and
bound the response size and the total time.
"""

from __future__ import annotations

import http.client
import ipaddress
import json
import socket
import ssl
import time
import urllib.parse
from typing import Any, List


class SSRFError(Exception):
    """Raised when a URL is not safe to fetch (non-https or non-public host)."""


def _ip_is_public(ip_str: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local  # blocks 169.254.0.0/16 incl. cloud metadata
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    ):
        return False
    # IPv4-mapped / 6to4 / Teredo can smuggle private targets through IPv6.
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return _ip_is_public(str(addr.ipv4_mapped))
        if addr.sixtofour is not None:
            return _ip_is_public(str(addr.sixtofour))
    return addr.is_global


def _resolved_ips(host: str, port: int) -> List[str]:
    """Resolve a host to its IP literals, or return [host] if already an IP."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise SSRFError(f"cannot resolve host: {host}") from e
    return [info[4][0] for info in infos]


def validate_url(url: str, *, allow_http: bool = False) -> None:
    """
    Validate that `url` is safe to fetch. Raises SSRFError otherwise.

    - Scheme must be https (http only if allow_http is explicitly set).
    - The host must resolve exclusively to public, routable IP addresses.
      Every resolved address is checked to defend against a hostname that
      resolves to a mix of public and private addresses.
    """
    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme != "https" and not (allow_http and scheme == "http"):
        raise SSRFError(f"scheme not allowed: {scheme!r}")
    host = parsed.hostname
    if not host:
        raise SSRFError("URL has no host")
    port = parsed.port or (443 if scheme == "https" else 80)
    ips = _resolved_ips(host, port)
    if not ips:
        raise SSRFError(f"host did not resolve: {host}")
    for ip in ips:
        if not _ip_is_public(ip):
            raise SSRFError(f"host {host} resolves to non-public address {ip}")


# ---------------------------------------------------------------------------
# Guarded fetch
# ---------------------------------------------------------------------------

DEFAULT_FETCH_TIMEOUT = 5.0
DEFAULT_MAX_BYTES = 1024 * 1024
DEFAULT_MAX_REDIRECTS = 3
USER_AGENT = "vouch-protocol/fetch (+https://vouch-protocol.com)"
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class FetchError(Exception):
    """Raised when a guarded fetch fails: bad status, too large, too slow, or
    a body that is not the expected format."""


def _public_ips(url: str) -> List[str]:
    """Validate `url` (https, public host) and return the addresses it resolves to."""
    validate_url(url)
    parsed = urllib.parse.urlparse(url)
    return _resolved_ips(parsed.hostname or "", parsed.port or 443)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """An HTTPS connection to an address that was already checked.

    The TLS handshake still uses the URL's hostname (SNI and certificate
    verification), but the TCP connection goes to the validated address, so a
    second DNS answer cannot swap in a private address between the check and
    the connect.
    """

    def __init__(self, host: str, port: int, ip: str, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_ip = ip

    def connect(self) -> None:
        sock = socket.create_connection((self._pinned_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def fetch_bytes(
    url: str,
    *,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    accept: str = "application/json",
) -> bytes:
    """GET `url` with the SSRF guard applied to every hop.

    - https only, and every address the host resolves to must be public.
    - The connection is pinned to the validated address.
    - Redirects are followed manually, up to `max_redirects`, and each target
      is validated again before it is fetched. `max_redirects=0` refuses them.
    - `timeout` bounds each network operation, and the whole fetch (all hops
      and the body) must finish within three times `timeout`.
    - The body is read up to `max_bytes`; anything larger is refused.

    Raises SSRFError for an unsafe URL and FetchError for any other failure.
    """
    deadline = time.monotonic() + 3 * timeout
    current = url
    for _hop in range(max_redirects + 1):
        ips = _public_ips(current)
        parsed = urllib.parse.urlparse(current)
        host = parsed.hostname or ""
        port = parsed.port or 443
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError(f"timed out fetching {url}")
        conn = _PinnedHTTPSConnection(host, port, ips[0], timeout=min(timeout, remaining))
        try:
            conn.request("GET", path, headers={"Accept": accept, "User-Agent": USER_AGENT})
            resp = conn.getresponse()
            if resp.status in _REDIRECT_STATUSES:
                location = resp.getheader("Location")
                if not location:
                    raise FetchError(f"redirect without a Location from {current}")
                current = urllib.parse.urljoin(current, location)
                continue
            if resp.status != 200:
                raise FetchError(f"HTTP {resp.status} from {current}")
            declared = resp.getheader("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise FetchError(f"response from {current} is larger than {max_bytes} bytes")
            body = bytearray()
            while True:
                if time.monotonic() > deadline:
                    raise FetchError(f"timed out reading {current}")
                chunk = resp.read(min(65536, max_bytes + 1 - len(body)))
                if not chunk:
                    break
                body.extend(chunk)
                if len(body) > max_bytes:
                    raise FetchError(f"response from {current} is larger than {max_bytes} bytes")
            return bytes(body)
        except (OSError, http.client.HTTPException) as exc:
            raise FetchError(f"cannot fetch {current}: {exc}") from exc
        finally:
            conn.close()
    raise FetchError(f"too many redirects fetching {url}")


def fetch_json(
    url: str,
    *,
    timeout: float = DEFAULT_FETCH_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> Any:
    """`fetch_bytes` plus a UTF-8 JSON parse. Raises FetchError on a bad body."""
    body = fetch_bytes(
        url,
        timeout=timeout,
        max_bytes=max_bytes,
        max_redirects=max_redirects,
        accept="application/json, application/did+json, application/ld+json",
    )
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise FetchError(f"{url} did not return JSON") from exc
