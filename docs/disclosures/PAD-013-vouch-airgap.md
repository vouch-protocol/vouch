# PAD-013: Method for Air-Gapped Identity Verification via Psychoacoustic Steganography

**Identifier:** PAD-013  
**Title:** Method for Air-Gapped Identity Verification via Psychoacoustic Steganography ("Vouch AirGap")  
**Publication Date:** January 20, 2026  
**Prior Art Effective Date:** January 20, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Biometrics / Signal Processing / Security / Deepfake Defense  
**Author:** Ramprasad Anandam Gaddam  

---

## 1. Abstract

A system and method for transmitting cryptographic proofs of identity and content authenticity over an "Air Gap"—analog sound waves traversing physical space—using advanced audio steganography techniques. The system encodes a cryptographic signature, identity assertion, or blockchain registry pointer into an audio stream using a combination of spread-spectrum watermarking, ultrasonic data beacons, and psychoacoustic masking.

This enables a receiving device (smartphone, laptop, specialized receiver) to **verify the authenticity of a speaker, a live broadcast, or a physical meeting** in real-time without requiring a direct digital network connection to the identity source. The protocol addresses the fundamental "Analog Hole" vulnerability where digital signatures are stripped when content traverses analog mediums (speaker-to-microphone paths).

The innovation introduces **"Zero-Network Handshake"** protocols enabling offline identity verification, **"Liveness Anchors"** that prove real-time presence versus playback, and **"Acoustic PKI"** for building trust networks through physical proximity verification.

---

## 2. Problem Statement

### 2.1 The Analog Hole Vulnerability
Digital signatures (C2PA, GPG, JWS) are cryptographically bound to file containers. When content traverses analog mediums, signatures are irrecoverably lost:
- Playing a signed audio file through speakers produces an unsigned acoustic signal.
- Recording a signed video with a camera produces an unsigned new file.
- Displaying a signed image on a screen and photographing it breaks provenance.

### 2.2 Real-Time Deepfake Threat
Modern voice synthesis can generate convincing real-time audio deepfakes:
- There is no reliable method to verify if a voice on a Zoom call, phone line, or podcast is the claimed speaker versus an AI clone.
- Existing liveness detection (blinking, motion) fails for audio-only channels.
- Post-hoc forensic analysis is too slow for real-time decision-making.

### 2.3 Physical Meeting Trust
In high-security scenarios (legal proceedings, financial transactions, diplomatic meetings):
- Participants need cryptographic proof that statements were made by verified identities.
- Network-based verification creates attack vectors and may be unavailable.
- No existing standard enables device-to-device identity verification purely through the physical audio channel.

### 2.4 Broadcast Authentication
Live broadcasts (news, emergency alerts, official announcements) are susceptible to:
- Deepfake impersonation of public figures.
- "Breaking news" attacks where fabricated content appears authentic.
- No viewer-verifiable proof of source authenticity.

---

## 3. Solution (The Invention)

### 3.1 The "Vouch AirGap" System Architecture

A multi-layer protocol for embedding, transmitting, and verifying cryptographic identity proofs through acoustic channels.

#### 3.1.1 Encoding Subsystem

The encoder generates and modulates cryptographic tokens into the audio stream:

**Token Structure:**
```json
{
  "version": "1.0",
  "type": "acoustic_anchor",
  "signer_did": "did:key:z6Mk...",
  "timestamp_utc": 1737352800,
  "nonce": "a7f3...",
  "sequence_number": 42,
  "liveness_challenge": "b9c2...",
  "signature": "ed25519:..."
}
```

**Encoding Modes:**

| Mode | Frequency Range | Use Case | Survivability |
|------|-----------------|----------|---------------|
| **Ultrasonic** | 17.5kHz - 20kHz | In-person meetings, quiet environments | High fidelity, limited range |
| **Near-Ultrasonic** | 14kHz - 17.5kHz | Broadcast, telephony | Medium compression survival |
| **Spread Spectrum** | 300Hz - 8kHz | Maximum robustness, noisy environments | Survives heavy compression |
| **Hybrid Adaptive** | Dynamic selection | Automatic environment optimization | Maximum reliability |

**Modulation Techniques:**
1. **Direct Sequence Spread Spectrum (DSSS):** The payload is XOR'd with a pseudo-random sequence derived from a shared seed, spreading energy across frequencies.
2. **Frequency Hopping:** Symbol transmission hops across frequency bins based on a deterministic pattern derived from the signer's public key.
3. **Echo Hiding:** Data bits are encoded in the delay pattern of artificially introduced echoes (survives aggressive compression).

#### 3.1.2 Psychoacoustic Masking Engine

To ensure imperceptibility, the encoder leverages the human auditory system's limitations:

1. **Simultaneous Masking:** Strong tones mask nearby frequencies. The system injects data at frequencies dominated by primary audio content.

2. **Temporal Masking:** Brief sounds mask signals occurring 2-200ms before and after. Data bursts are timed to coincide with transient audio events.

3. **Absolute Threshold:** Below ~20dB SPL at any frequency, sounds are inaudible. Data is injected at these absolute thresholds.

4. **Critical Band Analysis:** The encoder performs real-time FFT to identify spectral valleys where data can be hidden without perceptual impact.

**Adaptive Algorithm:**
```
for each audio_frame:
    spectrum = FFT(audio_frame)
    masking_threshold = calculate_psychoacoustic_mask(spectrum)
    available_capacity = find_below_threshold_bins(masking_threshold)
    inject_data_bits(available_capacity, payload_chunk)
    output = IFFT(modified_spectrum)
```

#### 3.1.3 Decoding Subsystem

The decoder performs real-time extraction and verification:

1. **Signal Capture:** Microphone input is digitized at 44.1kHz or higher.
2. **Pre-Processing:** Noise reduction, normalization, echo cancellation.
3. **Watermark Detection:**
   - Correlation analysis against known spreading sequences.
   - Peak detection in expected frequency bins.
   - Bit extraction using matched filtering.
4. **Error Correction:** Reed-Solomon or LDPC decoding recovers from partial signal loss.
5. **Signature Verification:** Ed25519 signature is verified against the claimed identity's public key.
6. **Liveness Validation:** Timestamp and nonce are checked for freshness (anti-replay).

#### 3.1.4 Zero-Network Handshake Protocol

Enables identity verification between two devices without network connectivity:

**Protocol Flow:**
```
Device A (Prover)                    Device B (Verifier)
     |                                      |
     |<---- Ultrasonic Challenge Beacon ----|
     |       (random nonce, verifier DID)   |
     |                                      |
     |---- Ultrasonic Response Beacon ----->|
     |  (signed: nonce + prover DID +       |
     |   timestamp + public key fragment)   |
     |                                      |
     |<---- Ultrasonic ACK -----------------| 
     |  (mutual authentication complete)    |
```

**Security Properties:**
- **Mutual Authentication:** Both parties verify each other.
- **Forward Secrecy:** Ephemeral session keys derived from ECDH over acoustic channel.
- **Replay Protection:** Nonce + timestamp window prevents recording attacks.
- **Proximity Proof:** Ultrasonic propagation limits verify physical proximity (<10m).

#### 3.1.5 Liveness Anchor System

Proves real-time presence versus playback of a pre-recorded session:

1. **Time-Variant Token:** The acoustic anchor includes a timestamp updated every 2-5 seconds.
2. **Challenge-Response:** A verifier can broadcast an ultrasonic challenge; the prover must sign and respond within 500ms (impossible for pre-recording).
3. **Environmental Fingerprint:** Optional inclusion of ambient acoustic features (room reverb signature) that differ between recording and playback environments.
4. **Heartbeat Pattern:** Continuous low-energy pulses confirm ongoing live presence.

---

## 4. Technical Implementation

### 4.1 Signal Processing Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                     ENCODER PIPELINE                            │
├─────────────────────────────────────────────────────────────────┤
│ Audio Input → Frame Buffer → FFT → Masking Analysis →          │
│ Capacity Estimation → Bit Injection → IFFT → Output Mix        │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     DECODER PIPELINE                            │
├─────────────────────────────────────────────────────────────────┤
│ Microphone → ADC → Frame Buffer → FFT → Correlation Detection →│
│ Bit Extraction → ECC Decode → Signature Verify → Trust Output  │
└─────────────────────────────────────────────────────────────────┘
```

### 4.2 Robustness Testing Matrix

| Attack/Degradation | Mitigation | Expected Survival |
|--------------------|------------|-------------------|
| MP3 Compression (128kbps) | Spread spectrum + ECC | >95% recovery |
| Speaker-to-Mic Recording | Adaptive pre-emphasis | >85% recovery |
| Background Noise (65dB) | Correlation detection | >80% recovery |
| Time Stretching (±10%) | Chirp synchronization | 100% recovery |
| Pitch Shifting (±2 semitones) | Frequency normalization | >90% recovery |
| Cropping/Editing | Redundant embedding | Partial recovery |

### 4.3 Implementation Platforms

| Platform | Implementation | Notes |
|----------|---------------|-------|
| iOS/Android | Native audio APIs | Real-time encoding/decoding |
| Web Browser | Web Audio API + WASM | Ultrasonic limited by speakers |
| Desktop | PortAudio + custom DSP | Full frequency range |
| Embedded | ARM DSP libraries | IoT/conferencing hardware |

---

## 5. Claims and Novel Contributions

### Claim 1: Analog-Resilient Provenance Chain
A method for maintaining the "Chain of Custody" for audio assets across analog transmission mediums (Speaker-to-Microphone) by embedding the cryptographic signature into the waveform itself, using psychoacoustic masking to ensure imperceptibility.

### Claim 2: Zero-Network Identity Handshake
A "Zero-Network Handshake" protocol where two offline devices exchange identity proofs and establish authenticated sessions solely via acoustic beacons, without any network infrastructure.

### Claim 3: Real-Time Liveness Verification
A method for verifying the real-time presence of a claimed identity during live audio communication by detecting time-variant, cryptographically signed watermarks and environmental fingerprints that cannot be pre-recorded.

### Claim 4: Adaptive Psychoacoustic Injection
A system that dynamically adjusts watermark injection based on real-time spectral analysis of the host audio, maximizing data capacity while remaining below human perceptual thresholds.

### Claim 5: Ultrasonic Proximity Verification
A method for cryptographically proving physical proximity between devices using ultrasonic beacon propagation characteristics, enabling "proof of presence" for high-security scenarios.

### Claim 6: Hybrid Modulation Mode Selection
A system that automatically selects optimal modulation parameters (frequency band, spreading factor, redundancy level) based on detected acoustic environment and transmission requirements.

### Claim 7: Acoustic PKI Bootstrap
A protocol for establishing PKI relationships through physical proximity, where devices that have successfully completed acoustic handshakes can cross-sign public keys, building an "acoustic web of trust."

### Claim 8: Broadcast Authentication Beacon
A method for embedding continuous authentication beacons in live broadcasts, enabling any receiver to verify source authenticity in real-time without additional network infrastructure.

### Claim 9: Challenge-Response Anti-Playback
A protocol where verifiers can issue random acoustic challenges that must be signed and returned within a time window too short for human-in-the-loop or network-round-trip attacks.

### Claim 10: Cross-Medium Authentication Bridge
A system enabling cryptographic identity to traverse multiple analog/digital medium transitions (digital→speaker→microphone→digital→speaker→microphone→digital) while maintaining verifiable provenance.

---

## 6. Security Analysis

### 6.1 Threat Model

| Threat | Mitigation |
|--------|------------|
| Watermark Removal | Multi-layer redundancy; graceful degradation |
| Watermark Forgery | Cryptographic signatures; requires private key |
| Replay Attack | Timestamp + nonce; challenge-response liveness |
| Analysis Attack | Psychoacoustic masking; imperceptible embedding |
| Jamming | Error correction; frequency hopping |

### 6.2 Limitations

- Requires compatible encoder/decoder on both ends.
- Ultrasonic mode limited by speaker/microphone frequency response.
- Very aggressive compression or low-bitrate codecs may partially degrade signal.
- Not a replacement for visual verification where applicable.

---

## 7. Use Cases

### 7.1 Video Conferencing Authentication
Live verification that a call participant is the claimed identity, defeating real-time voice cloning attacks.

### 7.2 Broadcast News Verification
Viewers can verify that a presidential address or emergency broadcast originates from the claimed source.

### 7.3 Courtroom Recording Authentication
Legal proceedings carry embedded provenance proving speaker identity and preventing post-hoc tampering.

### 7.4 Diplomatic/High-Security Meetings
Air-gapped environments where network-based verification is prohibited can still achieve cryptographic identity verification.

### 7.5 Podcast/Interview Authenticity
Listeners can verify that audio content features the claimed guests, not AI-generated impersonations.

---

## 8. Conclusion

The Vouch AirGap system addresses the fundamental vulnerability of digital signatures in analog transmission scenarios. By embedding cryptographic proofs directly into the acoustic waveform using psychoacoustic principles, the system enables identity verification and content authentication across speaker-to-microphone paths, offline environments, and real-time communication channels—capabilities previously impossible with container-based digital signatures.

---

## 9. References

- ISO/IEC 13818-7 (MPEG-2 AAC Psychoacoustic Model)
- D. Kirovski and H. Malvar, "Spread-Spectrum Watermarking of Audio Signals"
- B. Chen and G. Wornell, "Quantization Index Modulation" (IEEE)
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-012
- W3C Decentralized Identifiers (DIDs) v1.0
