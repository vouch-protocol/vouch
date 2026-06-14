# Robots and embodied agents

A robot is an agent with a body. Identity, accountability, and continuous trust
matter more, not less, when an agent can cause physical harm or move money in
the real world. Vouch covers the open identity layer for robots; richer
robot-lifecycle tooling builds on top of it.

## The same primitives apply

- Identity: a `did:vouch:agent` identity for the robot (the open agent DID
  profile in `docs/specs/`).
- Delegation: a delegation chain records who authorized the robot, on whose
  behalf, and within what limits, all verifiable.
- Continuous trust: the heartbeat runtime turns "valid at boot" into "still
  behaving now," so a robot has to keep proving itself.
- Revocation: pull a robot's authority the moment it goes wrong, and anyone can
  check the status.

## The robot-specific open piece: hardware root of trust

A software agent's key can live in a file. A robot should do better. The
hardware-root-of-trust profile binds the robot's DID to its secure element (a
TPM, a secure enclave, or an on-board AI module's enclave). The enclave holds
the signing key and signs the robot's heartbeats, so identity is anchored to the
physical device, not a config that can be copied. The open `did:vouch:agent`
profile defines the agent identity scheme; the embodied profile extends it for
hardware attestation.

## Open vs built on top

The identity, delegation, continuous-trust, and hardware-attestation profiles
are open Vouch. Operated robot-lifecycle products (lifecycle identity
management, model-and-config provenance, fleet trust at scale, and similar)
build on this open layer and are out of scope for the protocol itself.
