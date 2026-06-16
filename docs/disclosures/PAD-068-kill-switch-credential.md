# PAD-068: Verifiable Kill-Switch Credential with Attested-Authority Enforcement

**Identifier:** PAD-068  
**Title:** Method for a Verifiable Emergency-Stop (Kill-Switch) Credential Proving the Issuing Authority of a Robot Stop Command, Enforceable so that Only an Attested Authority Can Trigger It  
**Publication Date:** June 14, 2026  
**Prior Art Effective Date:** June 14, 2026  
**Status:** Public Disclosure (Defensive Publication)  
**Category:** Robotics / Physical Safety / Emergency Stop / Verifiable Credentials / Authorization  
**Author:** Ramprasad Anandam Gaddam  
**License:** Apache 2.0  
**Related:** PAD-064 (Hardware-Rooted Robot Identity), PAD-066 (Physical Capability Scope), PAD-067 (Robot-to-Robot Handshake)  

---

## 1. Abstract

A method for issuing and enforcing an emergency-stop ("kill-switch") command to a
robot as a verifiable credential that proves who issued the stop, what it targets,
and why, and that is enforceable so that **only an attested authority** can trigger
it. A robot (or a fleet controller) accepts a stop command only when it is a
validly signed KillSwitchCredential whose issuer is in the robot's set of attested
emergency-stop authorities, so a forged or unauthorized stop command is rejected,
and a genuine stop is non-repudiably attributable to its issuer.

Key innovations:

- **Stop command as a verifiable, attributable credential.** The emergency stop is
  not an anonymous signal but a signed credential proving the issuer, target, and
  reason, giving non-repudiation for both issuing and withholding a stop.
- **Attested-authority allowlist enforcement.** Acceptance requires the issuer to
  be in the robot's set of attested stop authorities, so only an authorized party
  can stop the robot, while still allowing any party to verify that a stop was
  legitimately issued.
- **Targetable scope.** A stop can target a single robot, a fleet, or a zone, and
  carry an optional scope, so emergency authority is expressible at the right
  granularity.

---

## 2. Problem Statement

### 2.1 Emergency-stop signals are unauthenticated

A physical e-stop or a network stop signal typically carries no proof of who
issued it. This permits both malicious denial-of-service (an attacker halting a
fleet) and unaccountable stops (no record of who stopped a robot or why).

### 2.2 No verifiable record of stop authority

After an incident, "who stopped the robot, and were they authorized" must be
answerable. Unsigned signals leave no verifiable record.

### 2.3 Authorization and verifiability are conflated

A system that restricts who can stop a robot often does so by a closed channel
that no third party can verify. The two properties (only an authority can trigger;
anyone can verify a stop was legitimate) should be separable.

---

## 3. Solution (The Invention)

A KillSwitchCredential is a Verifiable Credential whose subject carries:

```
{ "id": <target robot/fleet/zone>, "command": "emergency_stop",
  "reason": <text>, "issuedBy": <authority DID>, "scope"?: [...] }
```

signed (eddsa-jcs-2022) by the issuing authority. To act on a stop, the robot or
controller:

1. verifies the credential's Data Integrity proof, and
2. checks that the issuer DID is a member of the robot's configured set of
   attested emergency-stop authorities.

Both are required for the stop to take effect, so an unauthorized signer cannot
halt the robot. Independently, any third party can verify the credential to
confirm that a stop was legitimately issued by a named authority, giving
non-repudiation. The target field allows a single robot, a fleet, or a zone, and
the optional scope narrows the stop where needed.

---

## 4. Prior Art Differentiation

- **Hardware e-stop / safety PLC / ISO 13850.** Provide reliable physical stopping
  but no cryptographic proof of who issued the stop and no attested-authority
  authorization verifiable by third parties.
- **Network kill commands (fleet management).** Typically rely on channel
  authentication, not on a portable, verifiable, attributable credential that any
  party can check and that enforces an attested-authority allowlist.
- **PAD-064 / PAD-066.** Establish robot identity and physical scope; the present
  method adds the verifiable, attested-authority-enforced emergency-stop credential.

---

## 5. Technical Implementation

A reference implementation provides `build_killswitch_credential` and
`verify_killswitch_credential` (with an optional `trusted_authorities` allowlist),
reusing the eddsa-jcs-2022 credential format so the stop credential verifies with
the cross-language SDKs. The robot enforces the allowlist locally; verification of
issuance is open to any party.

---

## 6. Claims Summary

1. A method for an emergency-stop command to a robot expressed as a signed
   Verifiable Credential proving the issuing authority, the target, and the reason.
2. The method of claim 1 wherein the stop takes effect only when the issuer is a
   member of the robot's set of attested emergency-stop authorities, so an
   unauthorized party cannot stop the robot.
3. The method of claim 1 wherein any third party can verify the credential to
   confirm a stop was legitimately issued, giving non-repudiation.
4. The method of claim 1 wherein the target is a single robot, a fleet, or a zone,
   with an optional scope.
5. The method of claim 1 wherein the authorization (only an attested authority may
   trigger) and the verifiability (anyone may confirm legitimacy) are separable
   properties of the same credential.

---

## Prior Art Declaration

This document is published as a defensive disclosure to establish prior art as of
the date above. The methods are released under Apache 2.0 and may be freely
implemented, to prevent patenting by any party and to keep them available to the
open Vouch Protocol ecosystem and the robotics community.
