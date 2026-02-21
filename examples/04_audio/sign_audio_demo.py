#!/usr/bin/env python3
"""
Audio/Voice Signing Demo with Vouch Protocol

Demonstrates:
- Audio signing with watermarking
- Vouch Covenant (usage policies)
"""

import os
import sys
import wave
import struct
import math
from pathlib import Path

# Add vouch to path (relative to this script's location)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from vouch.audio import (
    AudioSigner,
    VouchCovenant,
    SpreadSpectrumWatermarker,
)
from vouch.media.native import generate_keypair

# =============================================================================
# Generate identity
# =============================================================================

private_key, did = generate_keypair()
print(f"🔑 Generated DID: {did[:45]}...")

# =============================================================================
# Create a sample audio file
# =============================================================================

audio_path = Path("/tmp/demo_voice.wav")

print("⚠️  Creating sample audio for demo...")
sample_rate = 16000
duration = 2.0
num_samples = int(sample_rate * duration)

samples = []
for i in range(num_samples):
    t = i / sample_rate
    envelope = 0.3 + 0.7 * (i / num_samples)
    sample = int(32767 * 0.5 * math.sin(2 * math.pi * 440 * t) * envelope)
    samples.append(sample)

with wave.open(str(audio_path), 'w') as wav_file:
    wav_file.setnchannels(1)
    wav_file.setsampwidth(2)
    wav_file.setframerate(sample_rate)
    wav_file.writeframes(struct.pack('<' + 'h' * len(samples), *samples))

print(f"   Created: {audio_path}")

# =============================================================================
# Show Vouch Covenant policies
# =============================================================================

print("\n📋 Vouch Covenant Policies Available:")

no_ai = VouchCovenant.no_ai_training()
print("\n1. no_ai_training():")
print(f"   - ai_training:   {no_ai.ai_training}")
print(f"   - voice_cloning: {no_ai.voice_cloning}")
print(f"   - ai_inference:  {no_ai.ai_inference}")

no_deriv = VouchCovenant.no_derivatives()
print("\n2. no_derivatives():")
print(f"   - derivative_works: {no_deriv.derivative_works}")
print(f"   - ai_training:      {no_deriv.ai_training}")

permissive = VouchCovenant.permissive()
print("\n3. permissive():")
print(f"   - ai_training:       {permissive.ai_training}")
print(f"   - voice_cloning:     {permissive.voice_cloning}")
print(f"   - commercial_use:    {permissive.commercial_use}")

# =============================================================================
# Initialize Audio Signer with Watermarker
# =============================================================================

print("\n📝 Initializing AudioSigner with spread-spectrum watermarker...")

watermarker = SpreadSpectrumWatermarker()
signer = AudioSigner(
    did=did,
    private_key=private_key,
    display_name="Demo Voice Actor",
    watermarker=watermarker,
)

print("   ✅ Signer initialized")
print("   Watermarker: Spread-Spectrum (Vouch Sonic)")
print("   Robustness:  Medium (survives compression)")

# =============================================================================
# Sign the audio with watermark
# =============================================================================

print("\n🎵 Signing audio with watermark and covenant...")

result = signer.sign_with_watermark(
    source_path=str(audio_path),
    output_path="/tmp/demo_voice_signed.wav",
    covenant=no_ai,  # Block AI training
)

if result.success:
    print("\n✅ Audio signed successfully!")
    print(f"   Original:    {result.source_path}")
    print(f"   Signed:      {result.output_path}")
    print(f"   Signer DID:  {result.signer_did[:40]}...")
    print(f"   Timestamp:   {result.timestamp}")
    print(f"   Watermarked: {result.watermark_embedded}")
    
    if result.covenant:
        print("\n📋 Embedded Covenant:")
        print(f"   AI Training:   {'✅ ALLOW' if result.covenant.ai_training else '❌ DENY'}")
        print(f"   Voice Cloning: {'✅ ALLOW' if result.covenant.voice_cloning else '❌ DENY'}")
        print(f"   Commercial:    {'✅ ALLOW' if result.covenant.commercial_use else '❌ DENY'}")
else:
    print(f"❌ Error: {result.error}")

print("""
🎵 AUDIO SIGNING COMPLETE!

   The signed audio at /tmp/demo_voice_signed.wav now contains:
   - Spread-spectrum watermark (survives compression)
   - Covenant policy (machine-readable usage rights)
   - Signer's DID for verification

🔒 COVENANT PROTECTS AGAINST:
   - AI voice cloning without permission
   - Training data scraping
   - Unauthorized commercial use
""")
