"""
Vouch Protocol Metrics.

Provides Prometheus-compatible metrics for monitoring verification
performance, cache efficiency, and error rates.
"""

import time
import logging
from typing import Optional, Dict, Any
from dataclasses import dataclass, field
from contextlib import contextmanager
import threading

logger = logging.getLogger(__name__)

# Try to import prometheus_client, but don't fail if not installed
try:
    from prometheus_client import Counter, Histogram, Gauge, CollectorRegistry, generate_latest

    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False


@dataclass
class MetricValue:
    """A simple metric value with labels."""

    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    metric_type: str = "counter"


class VouchMetrics:
    """
    Metrics collector for Vouch Protocol operations.

    Provides both Prometheus-compatible metrics (if prometheus_client
    is installed) and a simple in-memory metrics store.

    Example:
        >>> metrics = VouchMetrics()
        >>>
        >>> # Record events
        >>> metrics.record_signature()
        >>> metrics.record_verification(success=True, cached=True)
        >>>
        >>> # Use timer context
        >>> with metrics.verification_timer():
        ...     result = await verifier.verify(token)
        >>>
        >>> # Get metrics
        >>> print(metrics.get_stats())
    """

    def __init__(
        self,
        namespace: str = "vouch",
        enable_prometheus: bool = True,
        registry: Optional[Any] = None,
    ):
        """
        Initialize metrics collector.

        Args:
            namespace: Metric name prefix.
            enable_prometheus: Whether to register Prometheus metrics.
            registry: Optional Prometheus registry (uses default if None).
        """
        self._namespace = namespace
        self._lock = threading.Lock()

        # Simple in-memory stats
        self._counters: Dict[str, float] = {}
        self._histograms: Dict[str, list] = {}

        # Prometheus metrics (if available)
        self._prom_metrics = {}
        if PROMETHEUS_AVAILABLE and enable_prometheus:
            self._setup_prometheus_metrics(registry)

    def _setup_prometheus_metrics(self, registry: Optional[Any] = None):
        """Setup Prometheus metrics."""
        reg = registry or CollectorRegistry()

        self._prom_metrics["signatures_total"] = Counter(
            f"{self._namespace}_signatures_total", "Total number of signatures issued", registry=reg
        )

        self._prom_metrics["verifications_total"] = Counter(
            f"{self._namespace}_verifications_total",
            "Total number of verification attempts",
            ["status", "cached"],
            registry=reg,
        )

        self._prom_metrics["verification_duration"] = Histogram(
            f"{self._namespace}_verification_duration_seconds",
            "Verification latency in seconds",
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
            registry=reg,
        )

        self._prom_metrics["did_resolution_duration"] = Histogram(
            f"{self._namespace}_did_resolution_duration_seconds",
            "DID resolution latency in seconds",
            buckets=(0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
            registry=reg,
        )

        self._prom_metrics["cache_hit_ratio"] = Gauge(
            f"{self._namespace}_cache_hit_ratio", "Cache hit ratio (0-1)", registry=reg
        )

        self._prom_metrics["replays_blocked"] = Counter(
            f"{self._namespace}_replays_blocked_total", "Total replay attacks blocked", registry=reg
        )

        self._prom_metrics["rate_limit_exceeded"] = Counter(
            f"{self._namespace}_rate_limit_exceeded_total",
            "Total rate limit exceeded events",
            registry=reg,
        )

    def record_signature(self) -> None:
        """Record a signature issuance."""
        with self._lock:
            self._counters["signatures"] = self._counters.get("signatures", 0) + 1

        if "signatures_total" in self._prom_metrics:
            self._prom_metrics["signatures_total"].inc()

    def record_verification(self, success: bool, cached: bool = False) -> None:
        """Record a verification attempt."""
        key = f"verifications_{'success' if success else 'failure'}"
        with self._lock:
            self._counters[key] = self._counters.get(key, 0) + 1
            if cached:
                self._counters["cache_hits"] = self._counters.get("cache_hits", 0) + 1

        if "verifications_total" in self._prom_metrics:
            self._prom_metrics["verifications_total"].labels(
                status="success" if success else "failure", cached=str(cached).lower()
            ).inc()

    def record_verification_duration(self, duration_seconds: float) -> None:
        """Record verification latency."""
        with self._lock:
            if "verification_durations" not in self._histograms:
                self._histograms["verification_durations"] = []
            self._histograms["verification_durations"].append(duration_seconds)

        if "verification_duration" in self._prom_metrics:
            self._prom_metrics["verification_duration"].observe(duration_seconds)

    def record_did_resolution(self, duration_seconds: float) -> None:
        """Record DID resolution latency."""
        with self._lock:
            self._counters["did_resolutions"] = self._counters.get("did_resolutions", 0) + 1
            if "did_resolution_durations" not in self._histograms:
                self._histograms["did_resolution_durations"] = []
            self._histograms["did_resolution_durations"].append(duration_seconds)

        if "did_resolution_duration" in self._prom_metrics:
            self._prom_metrics["did_resolution_duration"].observe(duration_seconds)

    def record_replay_blocked(self) -> None:
        """Record a blocked replay attack."""
        with self._lock:
            self._counters["replays_blocked"] = self._counters.get("replays_blocked", 0) + 1

        if "replays_blocked" in self._prom_metrics:
            self._prom_metrics["replays_blocked"].inc()

    def record_rate_limit_exceeded(self) -> None:
        """Record a rate limit exceeded event."""
        with self._lock:
            self._counters["rate_limits"] = self._counters.get("rate_limits", 0) + 1

        if "rate_limit_exceeded" in self._prom_metrics:
            self._prom_metrics["rate_limit_exceeded"].inc()

    def update_cache_hit_ratio(self, ratio: float) -> None:
        """Update the cache hit ratio gauge."""
        if "cache_hit_ratio" in self._prom_metrics:
            self._prom_metrics["cache_hit_ratio"].set(ratio)

    @contextmanager
    def verification_timer(self):
        """Context manager for timing verifications."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.record_verification_duration(duration)

    @contextmanager
    def did_resolution_timer(self):
        """Context manager for timing DID resolutions."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.record_did_resolution(duration)

    def get_stats(self) -> Dict[str, Any]:
        """Get current metrics as a dictionary."""
        with self._lock:
            stats = dict(self._counters)

            # Calculate averages for histograms
            for name, values in self._histograms.items():
                if values:
                    stats[f"{name}_avg"] = sum(values) / len(values)
                    stats[f"{name}_count"] = len(values)
                    stats[f"{name}_p99"] = (
                        sorted(values)[int(len(values) * 0.99)]
                        if len(values) > 100
                        else max(values)
                    )

            # Calculate hit ratio
            total = stats.get("verifications_success", 0) + stats.get("verifications_failure", 0)
            if total > 0:
                stats["verification_success_rate"] = stats.get("verifications_success", 0) / total

            return stats

    def get_prometheus_metrics(self) -> Optional[bytes]:
        """Get metrics in Prometheus text format."""
        if PROMETHEUS_AVAILABLE and self._prom_metrics:
            return generate_latest()
        return None


# Global metrics instance
_global_metrics: Optional[VouchMetrics] = None


def get_metrics() -> VouchMetrics:
    """Get or create the global metrics instance."""
    global _global_metrics
    if _global_metrics is None:
        _global_metrics = VouchMetrics()
    return _global_metrics
