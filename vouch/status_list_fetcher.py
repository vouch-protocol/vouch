"""
HTTP fetcher for BitstringStatusListCredential (Specification §11.2).

Provides a reference verifier-side fetcher with an in-memory TTL cache. The
spec's `Implementations SHOULD cache status lists locally and refresh them
on verification failure` requirement is implemented here.

Production deployments with multiple verifier instances SHOULD substitute a
shared cache (Redis, CDN) and may want to plug in conditional-fetch handling
(ETag, Last-Modified) which this reference fetcher supports opportunistically.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import httpx


DEFAULT_CACHE_TTL_SECONDS = 300  # 5 minutes


class StatusListFetchError(Exception):
    """Raised when fetching a status list credential fails."""


@dataclass
class _CacheEntry:
    credential: Dict[str, Any]
    fetched_at: float
    etag: Optional[str] = None
    last_modified: Optional[str] = None


@dataclass
class StatusListFetcher:
    """
    Synchronous HTTP fetcher for BitstringStatusListCredential URLs.

    Uses an in-memory cache keyed by URL with a configurable TTL. On cache hit
    within TTL, returns the cached credential directly. On miss or expiry,
    issues a conditional GET (If-None-Match / If-Modified-Since when ETag /
    Last-Modified are known) and returns the refreshed credential.

    Attributes:
      cache_ttl_seconds: How long to consider a cached credential fresh.
        Default 300 (5 minutes).
      timeout_seconds: HTTP request timeout. Default 10.
      max_response_bytes: Reject responses larger than this. Default 5 MiB.
      client: Optional pre-configured `httpx.Client`. If not provided, a
        client is constructed on first use with sensible defaults.
    """

    cache_ttl_seconds: float = DEFAULT_CACHE_TTL_SECONDS
    timeout_seconds: float = 10.0
    max_response_bytes: int = 5 * 1024 * 1024
    client: Optional[httpx.Client] = None
    _cache: Dict[str, _CacheEntry] = field(default_factory=dict, init=False)

    def _get_client(self) -> httpx.Client:
        if self.client is None:
            self.client = httpx.Client(
                timeout=self.timeout_seconds,
                follow_redirects=False,
                headers={
                    "User-Agent": "vouch-protocol/status-list-fetcher",
                    "Accept": "application/json, application/ld+json",
                },
            )
        return self.client

    def get(self, url: str, *, force_refresh: bool = False) -> Dict[str, Any]:
        """
        Fetch the BitstringStatusListCredential at `url`.

        Args:
          url: HTTPS URL of the status list credential.
          force_refresh: If True, bypass the cache and fetch unconditionally.
            Verifiers SHOULD set this on verification failure to handle
            the case where the cached list is stale.

        Returns:
          The parsed credential as a dict.

        Raises:
          StatusListFetchError: on HTTP error, oversized response, or invalid JSON.
        """
        if not url:
            raise StatusListFetchError("url is required")
        if not url.startswith("https://"):
            raise StatusListFetchError(f"status list URL must be https://, got {url!r}")

        entry = self._cache.get(url)
        now = time.monotonic()
        if entry is not None and not force_refresh:
            age = now - entry.fetched_at
            if age < self.cache_ttl_seconds:
                return entry.credential

        headers: Dict[str, str] = {}
        if entry is not None:
            if entry.etag:
                headers["If-None-Match"] = entry.etag
            if entry.last_modified:
                headers["If-Modified-Since"] = entry.last_modified

        try:
            response = self._get_client().get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise StatusListFetchError(f"http error fetching {url}: {exc}") from exc

        if response.status_code == 304 and entry is not None:
            entry.fetched_at = now
            return entry.credential

        if response.status_code >= 400:
            raise StatusListFetchError(
                f"http {response.status_code} fetching {url}: {response.text[:200]}"
            )

        content_length = response.headers.get("content-length")
        if content_length is not None:
            try:
                if int(content_length) > self.max_response_bytes:
                    raise StatusListFetchError(
                        f"response too large ({content_length} bytes) for {url}"
                    )
            except ValueError:
                pass

        body = response.content
        if len(body) > self.max_response_bytes:
            raise StatusListFetchError(f"response too large ({len(body)} bytes) for {url}")

        try:
            credential = response.json()
        except ValueError as exc:
            raise StatusListFetchError(f"invalid JSON from {url}: {exc}") from exc

        if not isinstance(credential, dict):
            raise StatusListFetchError(
                f"expected JSON object from {url}, got {type(credential).__name__}"
            )

        self._cache[url] = _CacheEntry(
            credential=credential,
            fetched_at=now,
            etag=response.headers.get("etag"),
            last_modified=response.headers.get("last-modified"),
        )
        return credential

    def invalidate(self, url: Optional[str] = None) -> None:
        """
        Drop a cached entry for `url`, or the entire cache if `url` is None.
        """
        if url is None:
            self._cache.clear()
        else:
            self._cache.pop(url, None)

    def close(self) -> None:
        """Close the underlying httpx client if one was created."""
        if self.client is not None:
            self.client.close()
            self.client = None


__all__ = [
    "DEFAULT_CACHE_TTL_SECONDS",
    "StatusListFetchError",
    "StatusListFetcher",
]
