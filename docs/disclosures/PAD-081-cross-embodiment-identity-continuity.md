# PAD-081: Cross-Embodiment Identity Continuity Across Robot Bodies

**Identifier:** PAD-081  
**Title:** Method for Binding One Accountable Agent Identity Across a Sequence of Robot Bodies via a Chain of Embodiment Credentials, Each Re-Binding to a Body's Hardware Root and Signed by the Agent's Own Persistent Key  
**Publication Date:** July 4, 2026  
**Prior Art Effective Date:** July 4, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Embodied Agents / Identity Continuity  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-064 (Hardware-Rooted Robot Identity), PAD-078 (Robot Lifecycle)  

---

## 1. Abstract

A method for keeping one AI agent identity accountable as it moves between robot
bodies. An AI agent (a "mind": a policy with its own Vouch identity) can run on one
hardware-rooted robot body today and a different body tomorrow. An embodiment
credential binds the agent identity to a specific body and that body's hardware root
for a period, signed by the agent's own persistent key. Linking each embodiment to
the previous one forms a continuity chain a verifier walks to confirm the same
accountable agent persisted across bodies, re-binding to each body's hardware root as
it moved.

Key innovations:

- **Agent-signed embodiment binding.** Each embodiment is signed by the agent's own
  persistent key and binds the agent to a body and that body's hardware root, so the
  authorization to run on a body comes from the mind itself.
- **Continuity chain across fungible bodies.** Each embodiment names the body the
  agent left, so a verifier follows the chain and confirms the same agent identity
  persisted across a sequence of bodies, returning the current body.
- **The inverse of a custody chain.** Where an ownership custody chain holds one body
  constant as it passes between owners, this holds one mind constant as it passes
  between bodies, and the constant that signs every link is the agent identity.

---

## 2. Problem Statement

### 2.1 Agent minds are becoming portable across bodies

As embodied AI matures, the policy that controls a robot is increasingly separable
from the robot itself: the same agent can be deployed onto different bodies over
time, and bodies can be repurposed for different agents. There is no cryptographic
way today to prove that the accountable agent on one body is the same one that acted
on another.

### 2.2 A body-only identity cannot follow the mind

Hardware-rooted robot identity anchors the body, not the agent running on it. When
the agent moves to a new body, nothing ties its past accountability to its present
one, so an action on body B cannot be connected to the same agent's history on body A.

---

## 3. Solution (The Invention)

`build_embodiment(...)` issues an `AgentEmbodimentCredential` whose subject carries
the agent DID, the body DID, the body's hardware root, and the body the agent left,
signed eddsa-jcs-2022 by the agent's own key. `verify_embodiment(...)` checks the
proof and that the issuer is the agent itself. `verify_continuity_chain(...)` walks
an ordered list of embodiments, confirms every link verifies under the same agent
key, that each link's `fromBody` matches the previous link's `body`, and returns the
current body, so a verifier confirms the same accountable agent persisted across
bodies while re-binding to each body's hardware root. Because the credentials use the
shared JCS plus eddsa-jcs-2022 primitives, the same chain verifies across the
language SDKs. This is the open layer of signed credentials and chain verification;
managed key custody and fleet migration are out of scope.

---

## 4. Prior Art Differentiation

Verifiable Credentials, DID-based agent identity, hardware-rooted device identity,
and custody chains each exist as prior art, including this project's own work. This
disclosure does **not** claim those mechanisms in the abstract. What is differentiated
is the continuity of one agent across bodies:

- **The inverse-of-custody continuity chain**, holding one agent identity constant as
  it moves between bodies, with every link signed by that single persistent agent key.
- **Per-body hardware re-binding**, so each embodiment ties the mind to a specific
  body's hardware root at the time it ran there.
- **Agent-authorized embodiment**, so the mind itself authorizes each body it runs on,
  rather than a body asserting what it hosts.

---

## 5. Technical Implementation

A reference implementation provides `build_embodiment`, `verify_embodiment`, and
`verify_continuity_chain`, using the shared Data Integrity primitives so the same
embodiment chain verifies across the language SDKs.

---

## 6. Claims Summary

1. A method for binding one accountable agent identity across a sequence of robot
   bodies, wherein each embodiment credential binds the agent to a body and that
   body's hardware root and is signed by the agent's own persistent key.
2. The method of claim 1 wherein each embodiment names the body the agent left, so a
   verifier walks the chain and confirms the same agent identity persisted across
   bodies, returning the current body.
3. The method of claim 1 wherein every link of the continuity chain is verified under
   the same agent key, so a link signed by any other key breaks the continuity.
4. The method of claim 1 wherein each embodiment re-binds the agent to the hardware
   root of the body it runs on.
5. The method of claim 1 wherein the credentials use canonicalization and signature
   primitives shared across language SDKs, so the same chain verifies cross-language.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of the
date above. The methods are released under Apache 2.0 and may be freely implemented,
to prevent patenting by any party and to keep them available to the open Vouch
Protocol ecosystem and the robotics community.
