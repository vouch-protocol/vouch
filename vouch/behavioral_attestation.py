"""
Behavioral Attestation digest builder for the Heartbeat Protocol.

Implements the per-interval signal collection and digest computation
referenced in Specification §11.3. An agent records signals as it runs
(API calls, tokens consumed, resources accessed, optional intent-drift
scores); on each heartbeat the collector produces a `behavioralDigest`
object that is embedded in the heartbeat request.

Schema (Specification §11.3):

  {
   "apiCalls": <int>,
   "tokensConsumed": <int>,
   "resourcesAccessed": [<string>],
   "intentDriftScore": <float in [0, 1]>
  }

Higher `intentDriftScore` values indicate the agent's recent activity
diverges from its declared intent. The reference scoring algorithm
included here aggregates per-event drift samples; implementers MAY
substitute their own scorer.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


# Cap on how many distinct resource URIs are carried in a single digest
# to prevent unbounded growth. Beyond this cap, additional accesses are
# counted but not enumerated (the count remains accurate in apiCalls).
DEFAULT_MAX_RESOURCES = 64


class BehavioralAttestationError(Exception):
    """Raised on invalid configuration or input."""


@dataclass
class BehavioralSample:
    """One observed action with its drift score, used for testing and audit."""

    api_call: str
    tokens: int
    resource: Optional[str]
    drift: float
    timestamp_ns: int


@dataclass
class BehavioralCollector:
    """
    Thread-safe collector for per-interval behavioral signals.

    Typical lifecycle:
      collector = BehavioralCollector()
      # ... during heartbeat interval, agent records signals as they happen ...
      collector.record_api_call("https://api.example.com/orders", tokens=120)
      collector.record_api_call("https://api.example.com/orders", tokens=80)
      collector.record_resource_access("order:42")
      collector.record_drift_sample(0.05)
      # ... heartbeat time arrives ...
      digest = collector.digest()
      collector.reset() # start fresh for the next interval

    Attributes:
      max_resources: Soft cap on the number of distinct resource URIs
        enumerated in the digest. Counts beyond this cap are tracked
        via apiCalls / tokens but not listed individually.
      intent_drift_scorer: Optional override for how per-sample drift
        scores aggregate into the digest's `intentDriftScore`. Defaults
        to the arithmetic mean. Receives the list of recorded sample
        scores and returns a float in [0, 1].
    """

    max_resources: int = DEFAULT_MAX_RESOURCES
    intent_drift_scorer: Optional[Callable[[List[float]], float]] = None
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _api_calls: int = field(default=0, init=False)
    _tokens: int = field(default=0, init=False)
    _resources: List[str] = field(default_factory=list, init=False)
    _resources_seen: set = field(default_factory=set, init=False, repr=False)
    _drift_samples: List[float] = field(default_factory=list, init=False)
    _samples: List[BehavioralSample] = field(default_factory=list, init=False, repr=False)

    def record_api_call(
        self,
        endpoint: str,
        *,
        tokens: int = 0,
        resource: Optional[str] = None,
        drift: Optional[float] = None,
    ) -> None:
        """
        Record a single outbound API call.

        Args:
          endpoint: The URL or operation name being called.
          tokens: Tokens consumed by this call (LLM input + output).
          resource: Optional resource URI accessed. If supplied, is
            recorded in `resourcesAccessed`.
          drift: Optional intent-drift score for this call in [0, 1].
        """
        if tokens < 0:
            raise BehavioralAttestationError(f"tokens must be non-negative, got {tokens}")
        if drift is not None and not 0.0 <= drift <= 1.0:
            raise BehavioralAttestationError(f"drift must be in [0, 1], got {drift}")

        with self._lock:
            self._api_calls += 1
            self._tokens += int(tokens)
            if resource is not None and resource not in self._resources_seen:
                if len(self._resources) < self.max_resources:
                    self._resources.append(resource)
                self._resources_seen.add(resource)
            if drift is not None:
                self._drift_samples.append(float(drift))
            # Audit trail sample (capped for memory safety).
            if len(self._samples) < 1024:
                self._samples.append(
                    BehavioralSample(
                        api_call=endpoint,
                        tokens=int(tokens),
                        resource=resource,
                        drift=float(drift) if drift is not None else 0.0,
                        timestamp_ns=_now_ns(),
                    )
                )

    def record_tokens(self, count: int) -> None:
        """Record tokens consumed outside of an API call (e.g., local inference)."""
        if count < 0:
            raise BehavioralAttestationError(f"count must be non-negative, got {count}")
        with self._lock:
            self._tokens += int(count)

    def record_resource_access(self, resource: str) -> None:
        """Record a resource access not tied to a specific API call."""
        if not resource:
            raise BehavioralAttestationError("resource is required")
        with self._lock:
            if resource not in self._resources_seen:
                if len(self._resources) < self.max_resources:
                    self._resources.append(resource)
                self._resources_seen.add(resource)

    def record_drift_sample(self, drift: float) -> None:
        """Record a standalone intent-drift sample (e.g., from a similarity check)."""
        if not 0.0 <= drift <= 1.0:
            raise BehavioralAttestationError(f"drift must be in [0, 1], got {drift}")
        with self._lock:
            self._drift_samples.append(float(drift))

    def snapshot_samples(self) -> List[BehavioralSample]:
        """
        Return a copy of the per-sample audit trail.

        Useful for debugging or post-hoc analysis. Not included in the
        digest itself (which carries only aggregates).
        """
        with self._lock:
            return list(self._samples)

    def digest(self) -> Dict[str, Any]:
        """
        Return the behavioralDigest object suitable for embedding in a
        heartbeat request (Specification §11.3).
        """
        with self._lock:
            return {
                "apiCalls": self._api_calls,
                "tokensConsumed": self._tokens,
                "resourcesAccessed": list(self._resources),
                "intentDriftScore": self._compute_drift(),
            }

    def reset(self) -> None:
        """
        Clear all state. Call this after submitting a heartbeat so the
        next interval starts fresh.
        """
        with self._lock:
            self._api_calls = 0
            self._tokens = 0
            self._resources.clear()
            self._resources_seen.clear()
            self._drift_samples.clear()
            self._samples.clear()

    def _compute_drift(self) -> float:
        if not self._drift_samples:
            return 0.0
        if self.intent_drift_scorer is not None:
            score = float(self.intent_drift_scorer(list(self._drift_samples)))
            return max(0.0, min(1.0, score))
        return sum(self._drift_samples) / len(self._drift_samples)


def validate_behavioral_digest(digest: Dict[str, Any]) -> None:
    """
    Verifier-side structural validation of a behavioralDigest object.

    Raises BehavioralAttestationError on malformed input. Does NOT
    judge whether the values themselves are suspicious; that is policy.
    """
    if not isinstance(digest, dict):
        raise BehavioralAttestationError("digest must be a dict")

    for field_name in ("apiCalls", "tokensConsumed"):
        if field_name not in digest:
            raise BehavioralAttestationError(f"digest.{field_name} is required")
        if not isinstance(digest[field_name], int) or digest[field_name] < 0:
            raise BehavioralAttestationError(f"digest.{field_name} must be a non-negative integer")

    resources = digest.get("resourcesAccessed")
    if resources is None:
        raise BehavioralAttestationError("digest.resourcesAccessed is required")
    if not isinstance(resources, list):
        raise BehavioralAttestationError("digest.resourcesAccessed must be a list")
    for r in resources:
        if not isinstance(r, str):
            raise BehavioralAttestationError("digest.resourcesAccessed entries must be strings")

    drift = digest.get("intentDriftScore")
    if drift is None:
        raise BehavioralAttestationError("digest.intentDriftScore is required")
    if not isinstance(drift, (int, float)):
        raise BehavioralAttestationError("digest.intentDriftScore must be a number")
    if not 0.0 <= float(drift) <= 1.0:
        raise BehavioralAttestationError(f"digest.intentDriftScore must be in [0, 1], got {drift}")


# ---------------------------------------------------------------------------
# Reference intent-drift scorers
# ---------------------------------------------------------------------------


def mean_drift_scorer(samples: List[float]) -> float:
    """Arithmetic mean of drift samples. The default."""
    if not samples:
        return 0.0
    return sum(samples) / len(samples)


def max_drift_scorer(samples: List[float]) -> float:
    """Most cautious aggregator: the maximum sample dominates."""
    if not samples:
        return 0.0
    return max(samples)


def ewma_drift_scorer(alpha: float = 0.3) -> Callable[[List[float]], float]:
    """
    Exponentially weighted moving average scorer factory.

    Recent samples weigh more heavily. `alpha` is the smoothing factor
    in (0, 1]; higher values give recent samples more weight.
    """
    if not 0.0 < alpha <= 1.0:
        raise BehavioralAttestationError(f"alpha must be in (0, 1], got {alpha}")

    def scorer(samples: List[float]) -> float:
        if not samples:
            return 0.0
        ema = samples[0]
        for s in samples[1:]:
            ema = alpha * s + (1 - alpha) * ema
        return ema

    return scorer


def _now_ns() -> int:
    import time as _time

    return _time.time_ns()


__all__ = [
    "DEFAULT_MAX_RESOURCES",
    "BehavioralAttestationError",
    "BehavioralCollector",
    "BehavioralSample",
    "validate_behavioral_digest",
    "mean_drift_scorer",
    "max_drift_scorer",
    "ewma_drift_scorer",
]
