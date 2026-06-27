"""
Transport manager — the graceful-fallback routing middleware.

This is the piece a Vouch agent actually talks to. It holds an ordered list of
transports (identity-first UDNA in front, location-first HTTP behind) and a
single method, :meth:`dispatch`, that hides every routing decision behind one
call: *"deliver this envelope to this DID."* The agent never learns, nor needs
to, whether the bytes left over a Noise channel or an HTTPS POST.

Fallback contract — the manager walks its transports in preference order and,
for each:

  1. skips it if ``can_route`` says no (cheap pre-filter);
  2. skips it if ``resolve`` returns ``None`` (peer doesn't support it);
  3. attempts ``send`` if resolution succeeded.

A transport that raises :class:`TransportUnavailable` at any step — peer not on
the overlay, resolution failed, Noise handshake refused, connection dropped —
is treated as "not this one, try the next." The manager moves on. Only when
*every* transport has been exhausted does it raise the last error. The single
exception is :class:`PayloadIntegrityError`: if an envelope fails its own seal
check, the payload is corrupt and re-routing it would be dishonest, so the
manager refuses to fall back and raises immediately.

Payload preservation is structural: the *same* :class:`VouchEnvelope` instance
is handed to whichever transport wins. The Vouch credential, its Data Integrity
proof, the liability attestations, and the provenance metadata are never
re-signed, re-encoded, or stripped during the UDNA→HTTP transition — the
manager verifies the content digest once up front and then routes the bytes
untouched.
"""

from __future__ import annotations

import logging
from typing import List, Optional, Sequence

from .base import (
    DeliveryResult,
    PayloadIntegrityError,
    Transport,
    TransportError,
    TransportUnavailable,
)
from .envelope import VouchEnvelope

logger = logging.getLogger(__name__)


class TransportManager:
    """
    Dispatches Vouch envelopes across an ordered set of transports with
    automatic fallback.

    Args:
      transports: transports in preference order (first = most preferred).
        The conventional order is ``[UdnaTransport(...), HttpTransport(...)]``:
        try identity-first routing, fall back to DNS/IP + HTTP.
    """

    def __init__(self, transports: Sequence[Transport]) -> None:
        if not transports:
            raise ValueError("TransportManager requires at least one transport")
        self._transports: List[Transport] = list(transports)

    @classmethod
    def default(
        cls,
        *,
        udna_node: Optional["UdnaNode"] = None,
        udna_channel: Optional["UdnaChannel"] = None,
        private_key_jwk: Optional[str] = None,
        verify_ssl: bool = True,
    ) -> "TransportManager":
        """
        Build the canonical hybrid stack: UDNA preferred, HTTP fallback.

        UDNA is wired optimistically. Pass an explicit ``udna_node`` to use a
        ready-made node, or ``private_key_jwk`` + ``udna_channel`` to have a
        :class:`SirrayaUdnaNode` auto-built on the real ``udna_sdk``. If neither
        the SDK nor the prerequisites are available, the UDNA transport stays
        dormant and every dispatch falls straight through to HTTP — nothing to
        configure, nothing to fail.
        """
        from .http_transport import HttpTransport
        from .udna import UdnaTransport

        if udna_node is not None:
            udna = UdnaTransport(node=udna_node)
        else:
            udna = UdnaTransport.from_sdk(private_key_jwk=private_key_jwk, channel=udna_channel)

        return cls([udna, HttpTransport(verify_ssl=verify_ssl)])

    @property
    def transports(self) -> List[Transport]:
        """The transports in current preference order (read-only copy)."""
        return list(self._transports)

    async def dispatch(self, envelope: VouchEnvelope) -> DeliveryResult:
        """
        Deliver ``envelope`` to ``envelope.to_did`` using the first transport
        that can reach the peer.

        Returns:
          A :class:`DeliveryResult` recording which transport delivered and the
          full ordered list of transports attempted.

        Raises:
          PayloadIntegrityError: the envelope's cargo does not match its seal —
            fatal, never retried.
          TransportError: no transport could reach the peer; carries the last
            underlying failure.
        """
        # Verify the seal once, up front. A corrupt payload must never be
        # routed — falling back would just spread the corruption.
        if not envelope.verify_integrity(envelope.content_digest()):  # pragma: no cover
            raise PayloadIntegrityError("envelope failed its content-digest self-check")

        did = envelope.to_did
        attempts: List[str] = []
        last_error: Optional[TransportError] = None

        for transport in self._transports:
            try:
                if not await transport.can_route(did):
                    continue

                attempts.append(transport.name)

                peer = await transport.resolve(did)
                if peer is None:
                    # Transport cannot reach this peer → try the next one.
                    logger.debug(
                        "transport %s cannot resolve %s; falling back", transport.name, did
                    )
                    continue

                response = await transport.send(envelope, peer)

            except PayloadIntegrityError:
                # Fatal: do not fall back on a corrupted payload.
                raise
            except TransportUnavailable as exc:
                logger.debug("transport %s unavailable for %s: %s", transport.name, did, exc)
                last_error = exc
                continue
            except TransportError as exc:
                # Unexpected transport-layer error: record and keep falling back
                # so one misbehaving transport can't sink an otherwise routable
                # message.
                logger.warning("transport %s errored for %s: %s", transport.name, did, exc)
                last_error = exc
                continue

            logger.info(
                "delivered envelope %s to %s via %s (attempts: %s)",
                envelope.envelope_id,
                did,
                transport.name,
                attempts,
            )
            return DeliveryResult(
                ok=True,
                transport=transport.name,
                peer=peer,
                envelope_id=envelope.envelope_id,
                response=response,
                attempts=attempts,
            )

        # Every transport exhausted.
        detail = f": {last_error}" if last_error else ""
        raise TransportError(
            f"no transport could deliver to {did} (tried: {attempts or 'none'}){detail}"
        )

    async def close(self) -> None:
        """Close all underlying transports."""
        for transport in self._transports:
            try:
                await transport.close()
            except Exception:  # pragma: no cover - best-effort cleanup
                logger.debug("error closing transport %s", transport.name, exc_info=True)


# Imported for the type annotations on `default(...)` only.
from .udna import UdnaChannel, UdnaNode  # noqa: E402
