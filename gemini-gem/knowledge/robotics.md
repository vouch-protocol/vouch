# Robotics Reference: What Vouch Can Do for Robots

Vouch covers robots and embodied agents, not just software agents. The robotics
primitives are open, vendor-neutral, and built on the same eddsa-jcs-2022
Verifiable Credentials as the rest of Vouch, so they verify with every language
SDK (Python, Rust, TypeScript, Go, Swift, Kotlin). They live in the
`vouch.robotics` package. Everything below is built, tested, and shipped.

These are formats plus reference implementations. Hosted black-box storage and
fleet-scale kill-switch infrastructure are intentionally left to the deployer.

## The six capabilities

### 1. Hardware-rooted identity (`vouch.robotics.identity`)
A robot's software identity key is bound to a hardware root of trust (a TPM or a
secure element). The hardware root signs a binding over the robot's DID and key,
embedded in a RobotIdentityCredential that also carries make, model, serial, and
a lifecycle history. Verification checks both the credential proof and the
hardware attestation, so the identity cannot be cloned to other hardware. This is
the open alternative to closed or state-run robot-ID schemes.
Key functions: `mint_robot_identity`, `verify_robot_identity`,
`HardwareRootOfTrust` (the interface a TPM/secure-element backend satisfies),
`SoftwareRootOfTrust` (development reference), `lifecycle_event`.

### 2. Model and config provenance (`vouch.robotics.provenance`)
A signed ModelProvenanceAttestation records the model name, weights hash, safety
policy, and configuration hash running on a robot. It is re-signable on every
over-the-air update, with a `supersedes` link, so the chain answers "what model
and policy were running at any past time." The config hash is reproducible by any
verifier.
Key functions: `build_provenance_attestation`, `verify_provenance_attestation`,
`config_hash`.

### 3. Physical capability scope (`vouch.robotics.capability`)
Extends capability attenuation to the physical world: max force, max speed, a
lower max speed near humans, allowed zones, and shift windows, carried in a
PhysicalCapabilityScope credential and checked before each actuation. A delegated
scope must narrow (never broaden) its parent on every physical dimension.
Key functions: `build_physical_scope_credential`, `check_physical_action`,
`attenuates`, `PhysicalAction`.

### 4. Robot-to-robot trust handshake (`vouch.robotics.handshake`)
Two robots in different trust domains authenticate and agree a bounded-trust
cooperation session via three signed messages (HELLO, ACCEPT, CONFIRM). The
session scope is the intersection of what each robot offers, and the responder
checks the initiator's domain against its trust policy.
Key functions: `build_hello`, `build_accept`, `verify_accept`, `build_confirm`,
`verify_confirm`, `TrustPolicy`, `BoundedSession`.

### 5. Black box and kill switch (`vouch.robotics.blackbox`)
The black box is an append-only, AES-256-GCM-encrypted, hash-linked flight
recorder: payloads are confidential, the chain is tamper-evident without the key,
and only the key opens the payloads. The kill-switch credential is a verifiable
emergency stop that proves who issued it and, with an authority allowlist,
enforces that only an attested authority can trigger it.
Key functions: `BlackBoxLog`, `open_entry`, `verify_blackbox_chain`,
`build_killswitch_credential`, `verify_killswitch_credential`.

### 6. Scannable robot passport (`vouch.robotics.passport`)
A compact, signed passport in a `vouch-passport:` URI for a QR or NFC tag, so
anyone can check a robot's owner, authorized actions, certification, and standing
offline, with no network call.
Key functions: `build_passport`, `encode_passport`, `decode_passport`,
`verify_passport`.

## Quick answers

- "Can a robot prove which hardware it is?" Yes, via the hardware-rooted identity
  credential (capability 1).
- "Can I prove what model and safety policy a robot is running, even after an OTA
  update?" Yes, via the re-signable provenance attestation (capability 2).
- "Can I enforce that a robot slows down near people, or stays in its zone?" Yes,
  via the physical capability scope, checked before actuation (capability 3).
- "Can two robots from different fleets cooperate safely?" Yes, via the
  bounded-trust handshake (capability 4).
- "Can I prove who hit the emergency stop, and stop anyone else from doing it?"
  Yes, via the kill-switch credential with an attested-authority allowlist
  (capability 5).
- "Can a robot have a flight recorder that is private but tamper-evident?" Yes,
  via the encrypted black box (capability 5).
- "Can someone scan a robot to check it is legitimate?" Yes, via the scannable
  passport (capability 6).

## Status

All six are implemented with tests and a runnable demo
(`examples/robotics_demo.py`), documented in `docs/robotics.md`, with an interop
vector pinning the hardware-root binding and config hash. Defensive disclosures
PAD-064 (identity), PAD-065 (provenance), PAD-066 (physical scope), PAD-067
(handshake), PAD-068 (kill switch), PAD-069 (black box), and PAD-070 (passport)
cover the novel methods.
