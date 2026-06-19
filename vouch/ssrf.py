"""
SSRF protection for outbound fetches (did:web resolution, revocation lists,
status lists).

A verifier fetches URLs derived from attacker-controlled input (an issuer DID,
a credentialStatus entry). Without a guard, an attacker can point those at
internal services or the cloud metadata endpoint (169.254.169.254). This module
validates that a URL is https and resolves only to public, routable addresses,
and the callers disable redirects so a public host cannot 302 to an internal
one.
"""

from __future__ import annotations

import ipaddress
import socket
import urllib.parse
from typing import List


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
