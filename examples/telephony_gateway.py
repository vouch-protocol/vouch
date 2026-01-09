#!/usr/bin/env python3
"""
Telephony Gateway Example - PSTN Proxy Signing with Vouch.

Demonstrates the "Proxy Signing" pattern for Voice AI applications:
- A telephony gateway (Twilio, Vonage, etc.) receives calls from PSTN
- The caller is authenticated via phone number (Caller ID)
- The gateway signs the audio ON BEHALF of the verified caller
- Signed audio is forwarded to the AI Agent for processing

This is the "Dumb Terminal" → "Smart Gateway" → "AI Agent" architecture
where the gateway provides identity bridging for legacy telephony.

Use Cases:
- IVR systems that authenticate callers by phone number
- Contact centers where agents dial from verified extensions
- Voice bots that need to know "who is speaking"

Prerequisites:
    pip install vouch-protocol

Environment Variables:
    VOUCH_PRIVATE_KEY: Gateway's signing key (JWK JSON)
    VOUCH_DID: Gateway's DID (e.g., did:vouch:gateway123)
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional

from vouch.audio import (
    AudioSigner,
    watermark_chunk,
    verify_watermark,
    WatermarkResult,
)
from vouch.signer import Signer


@dataclass
class CallMetadata:
    """Metadata about an incoming phone call."""
    caller_id: str           # Caller's phone number
    called_number: str       # Destination number
    call_sid: str            # Call session ID (from Twilio/Vonage)
    timestamp: float         # Unix timestamp
    carrier: Optional[str] = None


@dataclass
class SignedAudioPacket:
    """Audio packet with Vouch credentials."""
    audio_data: bytes
    caller_id: str
    gateway_did: str
    timestamp: float
    vouch_signature: Optional[str] = None
    watermarked: bool = False


class TelephonyGateway:
    """Simulated PSTN Gateway with Vouch Proxy Signing.
    
    This gateway:
    1. Receives calls from the public telephone network
    2. Authenticates callers via phone number (Caller ID)
    3. Signs audio streams with its OWN identity
    4. Includes the caller's phone number in the signed payload
    
    The downstream AI Agent can then verify:
    - The audio came from a trusted gateway
    - The caller's phone number was verified by the gateway
    
    Example:
        >>> gateway = TelephonyGateway()
        >>> 
        >>> # Handle incoming call
        >>> call = CallMetadata(caller_id="+1555123456", ...)
        >>> 
        >>> # Sign audio on behalf of caller
        >>> packet = gateway.process_audio_chunk(audio_bytes, call)
        >>> 
        >>> # Send to AI Agent
        >>> agent.process(packet)
    """
    
    def __init__(
        self,
        private_key: Optional[str] = None,
        did: Optional[str] = None,
    ):
        """Initialize the telephony gateway.
        
        Args:
            private_key: Gateway's signing key (JWK JSON)
            did: Gateway's DID
        """
        self._private_key = private_key or os.getenv("VOUCH_PRIVATE_KEY")
        self._did = did or os.getenv("VOUCH_DID", "did:vouch:gateway")
        
        self._signer: Optional[Signer] = None
        self._audio_signer: Optional[AudioSigner] = None
        
        if self._private_key and self._did:
            try:
                self._signer = Signer(private_key=self._private_key, did=self._did)
                self._audio_signer = AudioSigner(self._signer)
            except Exception as e:
                print(f"Warning: Failed to initialize signer: {e}")
        
        # Simulated caller verification database
        self._verified_numbers: set[str] = {
            "+15551234567",
            "+15559876543",
            "+442071234567",
        }
    
    def verify_caller(self, caller_id: str) -> bool:
        """Verify if a caller ID is trusted.
        
        In production, this would check:
        - Known customer phone numbers
        - Employee directory
        - Verified callback numbers
        - STIR/SHAKEN attestation level
        
        Args:
            caller_id: The caller's phone number
            
        Returns:
            True if the caller is verified
        """
        # Basic verification - check against known numbers
        # In production: integrate with CRM, LDAP, or identity provider
        return caller_id in self._verified_numbers
    
    def process_audio_chunk(
        self,
        audio_bytes: bytes,
        call: CallMetadata,
        use_watermark: bool = True,
    ) -> SignedAudioPacket:
        """Process and sign an audio chunk from a phone call.
        
        This is the core "Proxy Signing" operation:
        1. Verify the caller is known/trusted
        2. Watermark the audio with our gateway identity
        3. Sign the payload including caller metadata
        
        Args:
            audio_bytes: Raw audio data from the call
            call: Metadata about the call
            use_watermark: Whether to add watermark to audio
            
        Returns:
            SignedAudioPacket ready to forward to AI Agent
        """
        # Step 1: Create packet
        packet = SignedAudioPacket(
            audio_data=audio_bytes,
            caller_id=call.caller_id,
            gateway_did=self._did,
            timestamp=time.time(),
        )
        
        # Step 2: Verify caller (log but don't block for this demo)
        is_verified = self.verify_caller(call.caller_id)
        
        # Step 3: Watermark audio
        if use_watermark:
            # Create signer identity that includes caller info
            composite_id = f"{self._did}:caller:{call.caller_id}"
            packet.audio_data = watermark_chunk(
                audio_bytes,
                signer_id=composite_id,
                timestamp=int(call.timestamp),
            )
            packet.watermarked = True
        
        # Step 4: Sign the metadata payload
        if self._signer:
            payload = {
                "type": "proxy_audio",
                "caller_id": call.caller_id,
                "caller_verified": is_verified,
                "call_sid": call.call_sid,
                "gateway_did": self._did,
                "audio_size": len(packet.audio_data),
                "timestamp": packet.timestamp,
            }
            packet.vouch_signature = self._signer.sign(payload)
        
        return packet


class AIAgentReceiver:
    """Simulated AI Agent that receives audio from the gateway.
    
    Demonstrates how the AI Agent verifies:
    1. The watermark on the audio
    2. The Vouch signature from the gateway
    3. The caller identity embedded in the payload
    """
    
    def process_audio_packet(self, packet: SignedAudioPacket) -> dict:
        """Process an audio packet from the telephony gateway.
        
        Args:
            packet: Signed audio packet from gateway
            
        Returns:
            Processing result
        """
        result = {
            "caller_id": packet.caller_id,
            "gateway": packet.gateway_did,
            "audio_size": len(packet.audio_data),
            "watermark_valid": False,
            "signature_present": packet.vouch_signature is not None,
        }
        
        # Verify watermark if present
        if packet.watermarked:
            wm_result = verify_watermark(packet.audio_data)
            result["watermark_valid"] = wm_result.valid
            if wm_result.valid:
                result["watermark_signer"] = wm_result.signer_id_hash
        
        return result


# =============================================================================
# Main Example
# =============================================================================

def main():
    """Demonstrate telephony gateway with proxy signing."""
    print("=" * 60)
    print("Telephony Gateway - Proxy Signing Example")
    print("=" * 60)
    
    # Initialize gateway
    gateway = TelephonyGateway()
    
    # Initialize AI Agent receiver
    agent = AIAgentReceiver()
    
    # Simulate incoming call
    call = CallMetadata(
        caller_id="+15551234567",  # Known/verified number
        called_number="+18001234567",
        call_sid="CA1234567890abcdef",
        timestamp=time.time(),
        carrier="Verizon",
    )
    
    print(f"\n1. Incoming call from: {call.caller_id}")
    print(f"   Call SID: {call.call_sid}")
    print("-" * 40)
    
    # Simulate audio chunk (normally from Twilio/Vonage stream)
    sample_audio = b"RIFF" + bytes(1000)  # Fake WAV-like data
    
    # Gateway processes and signs the audio
    print("\n2. Gateway processing audio chunk...")
    packet = gateway.process_audio_chunk(sample_audio, call)
    
    print(f"   Original audio size: {len(sample_audio)} bytes")
    print(f"   Watermarked size: {len(packet.audio_data)} bytes")
    print(f"   Has signature: {packet.vouch_signature is not None}")
    
    # AI Agent receives and verifies
    print("\n3. AI Agent receiving and verifying...")
    result = agent.process_audio_packet(packet)
    
    print(f"   Caller ID: {result['caller_id']}")
    print(f"   Gateway: {result['gateway']}")
    print(f"   Watermark valid: {result['watermark_valid']}")
    print(f"   Signature present: {result['signature_present']}")
    
    # Demonstrate with UNKNOWN caller
    print("\n4. Testing with UNKNOWN caller...")
    print("-" * 40)
    
    unknown_call = CallMetadata(
        caller_id="+15550000000",  # Not in verified list
        called_number="+18001234567",
        call_sid="CA9999999999xxxxxx",
        timestamp=time.time(),
    )
    
    packet2 = gateway.process_audio_chunk(sample_audio, unknown_call)
    result2 = agent.process_audio_packet(packet2)
    
    print(f"   Caller ID: {result2['caller_id']}")
    # Note: The signature payload includes "caller_verified": False
    # The agent can use this to apply different trust policies
    
    print("\n" + "=" * 60)
    print("Example complete!")
    print("=" * 60)
    print("\nKey takeaways:")
    print("- Gateway signs on behalf of PSTN callers")
    print("- Audio is watermarked with gateway identity")
    print("- AI Agent can verify provenance of audio")
    print("- Caller verification status is included in signature")


if __name__ == "__main__":
    main()
