# PAD-015: Method for Decentralized Crowd-Witnessed Media Capture Authentication

**Identifier:** PAD-015 
**Title:** Method for Decentralized Crowd-Witnessed Media Capture Authentication ("Ambient Witness Protocol") 
**Publication Date:** January 24, 2026 
**Prior Art Effective Date:** January 24, 2026 
**Status:** Public Disclosure (Defensive Publication) 
**Category:** Media Authentication / Decentralized Trust / Proximity Verification / Content Provenance 
**Author:** Ramprasad Anandam Gaddam 

---

## 1. Abstract

A novel decentralized protocol for establishing cryptographic proof that a media capture event occurred at a specific time and location, without requiring hardware-level attestation from cameras or recording devices. The "Ambient Witness Protocol" (AWP) leverages Bluetooth Low Energy (BLE) broadcasting from the capturing device to solicit signed attestations from nearby devices owned by independent third parties.

When a photographer captures an image, their device broadcasts a cryptographic challenge containing a hash commitment to the capture event. Nearby devices running compatible software automatically respond with signed attestations confirming they witnessed a device at that location at that time. These attestations are aggregated and embedded in the media file, creating a "crowd-witnessed" proof of capture.

This approach solves the fundamental "chicken-and-egg" problem of media provenance: cameras won't adopt hardware signing until it becomes popular, but authenticity cannot be proven without camera-level signing. AWP provides a software-only solution that works with existing devices, enabling immediate deployment while creating a bridge to future hardware adoption.

---

## 2. Problem Statement

### 2.1 The Hardware Adoption Gap

Current solutions for proving original media capture require:
- **C2PA-enabled cameras** (Sony, Leica, Nikon): Only available on expensive professional equipment
- **Trusted Execution Environments**: Requires smartphone manufacturers to participate
- **Blockchain timestamping**: Proves hash existence, not physical presence at capture

**Result**: No practical way to prove a person was present when they captured media.

### 2.2 The Self-Attestation Problem

With self-sovereign identity systems (including Vouch Protocol):
- Anyone can generate a keypair and claim any identity
- Anyone can sign any image and claim they captured it
- The signature proves WHO signed, but not IF they were present at capture

**Attacker Scenario**:
```
1. Attacker downloads war zone photograph from news wire
2. Attacker signs it with their own Vouch identity
3. Attacker claims they captured it
4. No cryptographic way to disprove the claim
```

### 2.3 The Camera Manufacturer Inertia

Manufacturers have no commercial incentive to implement signing:
- Adds cost and complexity
- No consumer demand (feature is invisible)
- Creates potential liability
- Requires PKI infrastructure investment

**Result**: Waiting for camera adoption is not a viable strategy.

---

## 3. Solution: The Ambient Witness Protocol

### 3.1 Core Concept

Instead of relying on the capturing device to prove authenticity, leverage the CROWD of nearby devices as independent witnesses.

**Key Insight**: At any real-world capture event, there are typically multiple people with smartphones nearby. These devices can serve as decentralized witnesses to the capture event, even if their owners never consciously participate.

### 3.2 Protocol Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│          AMBIENT WITNESS PROTOCOL FLOW               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                       │
│ PHASE 1: CAPTURE INITIATION                        │
│ ┌──────────────────────────────────────────────────────────────────────┐ │
│ │ 📸 Photographer presses shutter                   │ │
│ │   ↓                                │ │
│ │ 📱 Device generates:                         │ │
│ │   • Random nonce (N)                        │ │
│ │   • Timestamp (T)                         │ │
│ │   • Location hash (H(GPS))                     │ │
│ │   • Device public key fingerprint (FP)               │ │
│ │   ↓                                │ │
│ │ 📡 BLE Advertisement broadcast:                   │ │
│ │   "VOUCH-WITNESS|v1|H(N||T||GPS)||FP"               │ │
│ └──────────────────────────────────────────────────────────────────────┘ │
│                                       │
│ PHASE 2: WITNESS RESPONSE                         │
│ ┌──────────────────────────────────────────────────────────────────────┐ │
│ │ 📱📱📱 Nearby devices (within BLE range ~10-100m):         │ │
│ │   ↓                                │ │
│ │ [Automatic background process]                    │ │
│ │   • Receive VOUCH-WITNESS broadcast                │ │
│ │   • Record: received_time, own_location, signal_strength      │ │
│ │   • Generate signed attestation:                  │ │
│ │    {                               │ │
│ │     "type": "witness_attestation",                │ │
│ │     "witness_did": "did:key:z6MkWitness...",           │ │
│ │     "observed_hash": "H(N||T||GPS)",               │ │
│ │     "observed_fingerprint": "FP",                │ │
│ │     "witness_time": 1737730000,                 │ │
│ │     "witness_location_hash": "H(witness_GPS)",          │ │
│ │     "signal_strength": -45,                   │ │
│ │     "signature": "Ed25519(...)"                 │ │
│ │    }                               │ │
│ │   ↓                                │ │
│ │ 📡 Response via BLE GATT characteristic or direct connection    │ │
│ └──────────────────────────────────────────────────────────────────────┘ │
│                                       │
│ PHASE 3: ATTESTATION AGGREGATION                      │
│ ┌──────────────────────────────────────────────────────────────────────┐ │
│ │ 📸 Capturing device collects attestations (timeout: 5 seconds)   │ │
│ │   ↓                                │ │
│ │ Creates "Witness Bundle":                      │ │
│ │   • Original nonce (N) - reveals commitment            │ │
│ │   • Capture timestamp (T)                     │ │
│ │   • Location (GPS or H(GPS))                    │ │
│ │   • Array of witness attestations                 │ │
│ │   • Capture signature from photographer              │ │
│ │   ↓                                │ │
│ │ Embedded in image metadata or sidecar file              │ │
│ └──────────────────────────────────────────────────────────────────────┘ │
│                                       │
│ PHASE 4: VERIFICATION                           │
│ ┌──────────────────────────────────────────────────────────────────────┐ │
│ │ 🔍 Verifier receives image with Witness Bundle            │ │
│ │   ↓                                │ │
│ │ Checks:                               │ │
│ │   ✓ Photographer's signature valid                 │ │
│ │   ✓ Each witness attestation signature valid            │ │
│ │   ✓ Witness timestamps within acceptable window          │ │
│ │   ✓ Signal strengths consistent with proximity           │ │
│ │   ✓ Witness DIDs are independent (not Sybil attack)        │ │
│ │   ↓                                │ │
│ │ Trust Score = f(num_witnesses, independence, signal_quality)     │ │
│ └──────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.3 Trust Score Calculation

```python
def calculate_witness_trust_score(witness_bundle: WitnessBundle) -> float:
  """
  Calculate trust score from witness attestations.

  Returns: 0.0 (no witnesses) to 1.0 (maximum confidence)
  """
  witnesses = witness_bundle.attestations

  if len(witnesses) == 0:
    return 0.0

  # Base score from witness count (logarithmic diminishing returns)
  count_score = min(1.0, math.log2(len(witnesses) + 1) / 4)

  # Independence score (check for Sybil patterns)
  unique_dids = set(w.witness_did for w in witnesses)
  independence_score = len(unique_dids) / len(witnesses)

  # Signal consistency (witnesses should have varying signal strengths)
  signals = [w.signal_strength for w in witnesses]
  signal_variance = np.std(signals) if len(signals) > 1 else 0
  signal_score = min(1.0, signal_variance / 20) # Expect ~20dB variance

  # Time consistency (all witnesses within tight window)
  times = [w.witness_time for w in witnesses]
  time_spread = max(times) - min(times)
  time_score = 1.0 if time_spread < 5 else max(0, 1 - time_spread / 30)

  # Combine scores
  trust_score = (
    count_score * 0.4 +
    independence_score * 0.3 +
    signal_score * 0.15 +
    time_score * 0.15
  )

  return trust_score
```

**Trust Score Interpretation:**

| Score | Witnesses | Interpretation |
|-------|-----------|----------------|
| 0.90+ | 8+ diverse | 🟢 Very High Confidence |
| 0.70-0.89 | 4-7 | 🟢 High Confidence |
| 0.50-0.69 | 2-3 | 🟡 Medium Confidence |
| 0.25-0.49 | 1 | 🟡 Low Confidence |
| 0.00-0.24 | 0 | 🔴 Unwitnessed |

---

## 4. Privacy Considerations

### 4.1 Witness Privacy

| Concern | Mitigation |
|---------|------------|
| Location tracking | Witnesses only share hash of location, not coordinates |
| Photo access | Witnesses never see the captured content |
| Identity exposure | Witness DIDs are pseudonymous |
| Background usage | User can control battery/privacy tradeoffs in settings |

### 4.2 Photographer Privacy

| Concern | Mitigation |
|---------|------------|
| Precise location | Can use coarse location hash (100m grid) |
| Timing exposure | Timestamps can be rounded to minute |
| Identity linkage | Different DIDs can be used per-context |

### 4.3 Consent Model

**Opt-in by default**: Users must explicitly enable witness mode.

**Three modes:**
1. **Passive Witness**: Receive broadcasts, auto-respond (background)
2. **Active Witness**: Explicit confirmation before responding
3. **Disabled**: Do not participate

---

## 5. Security Analysis

### 5.1 Attack Resistance

| Attack | Description | Countermeasure |
|--------|-------------|----------------|
| **Sybil Attack** | Attacker creates many fake witnesses | DID age verification, reputation scoring, signal strength analysis |
| **Replay Attack** | Reuse old attestations for new capture | Nonce in challenge, tight timestamp window |
| **Collusion** | Photographer and witnesses conspire | Geographic diversity check, independent relationship analysis |
| **Fake Broadcast** | Generate broadcast without real capture | Challenge-response timing constraints |
| **Signal Spoofing** | Fake signal strength values | Cross-validation between multiple witnesses |

### 5.2 Limitations

1. **Requires nearby witnesses**: Isolated captures have no witnesses
2. **Not proof of content**: Witnesses attest to presence, not what was captured
3. **Battery impact**: Background BLE scanning consumes power
4. **Adoption dependency**: Value increases with more participants

### 5.3 Game-Theoretic Stability

**Honest witness incentives:**
- Reputation points for accurate witnessing
- Future verification value for own captures
- Social good motivation

**Attack disincentives:**
- Reputation slashing for false attestations
- Cryptographic paper trail enables post-hoc detection
- Economic cost of Sybil attack at scale

---

## 6. Claims and Novel Contributions

### Claim 1: Crowd-Sourced Capture Authentication
A method for proving media capture event occurrence through cryptographically signed attestations from independent nearby devices, without requiring hardware-level camera attestation.

### Claim 2: BLE-Based Witness Discovery
A protocol using Bluetooth Low Energy advertising for automatic discovery and attestation exchange between capturing devices and witness devices, requiring no user interaction.

### Claim 3: Privacy-Preserving Presence Proof
A witness attestation format that proves proximity to a capture event without revealing the witness's precise location, the captured content, or enabling tracking of movement patterns.

### Claim 4: Sybil-Resistant Witness Scoring
A trust scoring algorithm that evaluates witness independence using DID relationship graphs, signal strength variance analysis, and temporal consistency checks.

### Claim 5: Commitment-Reveal Capture Binding
A cryptographic protocol where the capturing device first broadcasts a hash commitment, then reveals the preimage only after collecting attestations, preventing attestation forgery.

### Claim 6: Signal Strength Cross-Validation
A method for detecting spoofed proximity claims by comparing signal strength measurements reported by multiple witnesses, identifying inconsistencies indicative of false attestations.

### Claim 7: Decentralized Witness Reputation
A reputation system for witness DIDs that tracks attestation accuracy over time, rewarding honest participants and penalizing those who provide false or inconsistent attestations.

### Claim 8: Progressive Trust Aggregation
A trust model where confidence in capture authenticity increases with the number and diversity of independent witnesses, providing granular trust levels rather than binary verification.

### Claim 9: Offline Attestation Batching
A method for witnesses to batch and submit attestations when connectivity is restored, enabling the protocol to function in low-connectivity environments.

### Claim 10: Inter-Protocol Attestation Bridging
A mechanism for integrating ambient witness attestations with other provenance systems (C2PA, Vouch Sonic), creating layered authenticity proofs combining multiple verification methods.

---

## 7. Implementation Architecture

### 7.1 Mobile SDK Components

```
┌─────────────────────────────────────────────────────────────────┐
│          AMBIENT WITNESS SDK              │
├─────────────────────────────────────────────────────────────────┤
│                                 │
│ ┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐ │
│ │  BLE Manager  │ │ Attestation Mgr │ │ Trust Scorer  │ │
│ │         │ │         │ │         │ │
│ │ • Advertise   │ │ • Generate   │ │ • Aggregate   │ │
│ │ • Scan     │ │ • Validate   │ │ • Analyze    │ │
│ │ • Connect    │ │ • Store     │ │ • Score     │ │
│ └────────┬────────┘ └────────┬────────┘ └────────┬────────┘ │
│      │          │          │      │
│      └────────────────────┼────────────────────┘      │
│                │                 │
│          ┌───────────▼───────────┐          │
│          │  Identity Manager  │          │
│          │  (Vouch Protocol)  │          │
│          └───────────────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

### 7.2 Platform Integration Points

| Platform | Integration Method |
|----------|-------------------|
| iOS Camera App | CameraCapture extension with CoreBluetooth |
| Android Camera | Camera2 API integration with BLE advertising |
| React Native | Cross-platform SDK with native modules |
| Web (Progressive) | Web Bluetooth API (Chrome, Edge) |
| Desktop | Companion mobile app for witness relay |

### 7.3 Backend Services (Optional)

For enhanced Sybil resistance and reputation management:

```
┌─────────────────────────────────────────────────────────────────┐
│         VOUCH WITNESS REGISTRY              │
├─────────────────────────────────────────────────────────────────┤
│ • DID reputation scores                     │
│ • Attestation history (anonymized)               │
│ • Sybil detection patterns                   │
│ • Geographic witness density maps                │
│ • Trust score verification service               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 8. Use Cases

### 8.1 Citizen Journalism
Protesters document police activity with crowd-witnessed photos, providing cryptographic evidence that the photographer was physically present.

### 8.2 War Zone Documentation
Journalists in conflict zones have other journalists and witnesses attest to capture events, creating multi-party provenance for sensitive images.

### 8.3 Real Estate Photography
Property photos are witnessed by neighbors' phones, proving the photo was actually taken at the claimed location.

### 8.4 Event Photography
Wedding/concert photographers have attendees' phones automatically witness capture events, proving photos are from the actual event.

### 8.5 Insurance Claims
Accident scene photos are witnessed by bystanders, providing independent verification of when and where damage documentation occurred.

### 8.6 Scientific Field Research
Researchers documenting specimens in the field have team members' devices witness captures, creating auditable provenance for published images.

---

## 9. Future Extensions

### 9.1 Hardware Integration
When cameras do support signing, AWP attestations can supplement hardware attestations for defense-in-depth.

### 9.2 IoT Witness Networks
Fixed IoT devices (security cameras, smart city infrastructure) could serve as permanent witness infrastructure.

### 9.3 Mesh Network Attestation
In low-connectivity areas, witnesses could relay attestations through multi-hop mesh networks.

### 9.4 Incentive Layer
Blockchain-based incentive mechanisms for honest witnessing (reputation tokens, micropayments).

---

## 10. Conclusion

The Ambient Witness Protocol provides a practical, deployable solution to the media authenticity problem without waiting for hardware adoption. By leveraging the ubiquity of smartphones and the physics of Bluetooth proximity, AWP creates a decentralized trust network where presence is proven through independent crowd attestation. This approach aligns incentives for honest participation while making attacks economically and practically difficult.

---

## 11. References

- Bluetooth Low Energy (BLE) Specification 5.0+
- Decentralized Identifiers (DIDs) v1.0
- Content Authenticity Initiative (C2PA) Specification
- Vouch Protocol: Prior Art Disclosures PAD-001 through PAD-014
- Sybil Attack Resistance in Peer-to-Peer Networks (literature)
- Proximity-Based Authentication Systems (academic surveys)
