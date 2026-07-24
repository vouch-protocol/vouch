# Robotics: the complete guide to Vouch for robots and embodied agents

Vouch gives robots and embodied agents the same identity, accountability, and
continuous trust it gives software agents, and adds the pieces that only matter
once an agent has a body and can cause physical harm. This guide teaches every
robotics capability end to end: what it is, the problem it closes, how it works,
the API, a worked example, and exactly what verification checks.

## The shared foundation

Every robotics primitive is built on the same machinery as the rest of Vouch, so
there is nothing new to trust at the cryptographic layer:

- Credentials are W3C Verifiable Credentials with an `eddsa-jcs-2022` Data
  Integrity proof (Ed25519 signature over the RFC 8785 JCS canonical bytes,
  SHA-256 digest, `proofValue` as multibase base58btc).
- Binary values that are not keys (attestations, config hashes, ciphertext,
  entry hashes) use multibase base64url, a leading `u` then base64url-no-pad.
- The same credential verifies in every language. The logic lives once in the
  Rust core (`core/vouch-core`, module `robotics`) and is exposed to Swift,
  Kotlin/JVM, .NET, C/C++, and the browser through the UniFFI and WASM wrappers;
  Python, TypeScript, and Go each carry a byte-identical reference
  implementation (`vouch.robotics`, `packages/sdk-ts/src/robotics`,
  `go-sidecar/robotics`). A robotics credential signed in any one of them
  verifies in all the others, proven by the shared interop vector in
  `test-vectors/robotics/vector.json`.

These are open formats plus reference implementations. Hosted black-box storage
and fleet-scale kill-switch infrastructure are left to whoever deploys them.

A design rule runs through the whole module: the core is hardware-agnostic and
deterministic. It never reaches for a clock, a random number, or a TPM on its
own. Timestamps, nonces, session ids, and hardware attestations are passed in by
the caller, so output is reproducible and a real deployment can route signing to
a secure element while a test routes it to a software key.

---

## 1. Hardware-rooted identity

`vouch.robotics.identity`

What it is: a `RobotIdentityCredential` that binds a robot's software identity
key to a physical hardware root of trust (a TPM, a secure enclave, or an on-board
secure element), alongside its make, model, serial, owner, and lifecycle history.

The problem it closes: a software-only identity can be copied to another machine.
If a robot's DID and key live in a config file, a cloned robot is
indistinguishable from the original. Hardware rooting makes the identity
non-transferable: it is provably tied to one piece of silicon.

How it works: the robot self-issues the credential with its own Ed25519 key. The
hardware root signs a binding, the JCS canonical bytes of
`{"key": <robot key multibase>, "robotDid": <robot DID>}`, and that signature is
embedded as `credentialSubject.hardwareRoot.attestation` next to the hardware
root's own public key. Verification therefore checks two independent signatures:
the credential proof (the robot key signed the document) and the hardware
attestation (the hardware root signed the binding tying that key to that DID).

The API: `mint_robot_identity` and `verify_robot_identity`, plus the
`robot_identity_binding` helper that returns the exact bytes a TPM-backed root
must sign (so a hardware backend can sign them externally). The reference SDKs add
a `SoftwareRootOfTrust` for development and a `HardwareRootOfTrust` interface a
real backend implements.

Worked example (Python):

```python
from vouch.robotics import identity

root = identity.SoftwareRootOfTrust(kind="TPM")          # a real deployment uses the TPM
cred = identity.mint_robot_identity(
    robot_signer, root,
    make="Acme Robotics", model="AR-7", serial="SN-000123",
    owner="did:web:owner.example.com",
)
ok, subject = identity.verify_robot_identity(cred, robot_signer.public_key())
```

Security boundary: verification fails closed if the type is wrong, the credential
proof is invalid, the hardware public key is missing or not Ed25519, or the
attestation does not verify against the binding. An attacker who
swaps in their own hardware key and re-signs the credential still fails, because
the attestation no longer matches the `{key, robotDid}` binding.

---

## 2. Model and config provenance

`vouch.robotics.provenance`

What it is: a signed `ModelProvenanceAttestation` recording the
vision-language-action model name, the weights hash, the safety policy, and a
hash of the running configuration.

The problem it closes: "what software and safety policy was this robot running
when the incident happened?" Without a signed record, the answer is whatever the
logs say after the fact. Provenance makes it cryptographic and tamper-evident,
and it survives over-the-air updates.

How it works: the attestation carries a `vla` block with `modelName`,
`weightsHash`, `safetyPolicy`, an optional `version`, and a `configHash`. The
config hash is the multibase SHA-256 of the JCS-canonical config object, so any
verifier reproduces it from the same config and detects drift. On an OTA update
the robot re-signs a new attestation with a `supersedes` link to the previous
one, forming a chain you can walk to answer "what was running at time T."

The API: `build_provenance_attestation`, `verify_provenance_attestation`, and
`config_hash`. Passing the config to the verifier additionally checks that the
recorded `configHash` reproduces.

Worked example (TypeScript):

```ts
import { buildProvenanceAttestation, verifyProvenanceAttestation } from '@vouch-protocol-official/sdk';

const att = await buildProvenanceAttestation(signer, {
  robotDid, modelName: 'openvla-7b', weightsHash: 'u...', safetyPolicy: 'did:web:authority#policy-v3',
  config: { temperature: 0.0, max_torque: 12.5, guardrails: ['no_humans_zone'] },
});
const { ok, subject } = verifyProvenanceAttestation(att, publicKey, config);
```

Security boundary: verification fails on a wrong type, an invalid proof, or, when
a config is supplied, a `configHash` that does not match. A robot running a
different config than the one attested is detectable by anyone holding the
expected config.

---

## 3. Physical capability scope

`vouch.robotics.capability`

What it is: a `PhysicalCapabilityScope` credential carrying physical limits, max
force, max speed, a tighter speed cap near humans, allowed zones, and shift
windows, that a controller checks before every actuation.

The problem it closes: a permission like "operate the arm" says nothing about how
hard or how fast. Physical scope makes the bound cryptographically enforceable
and, crucially, makes delegated authority shrink-only so a sub-task can never
quietly grant itself more force or a wider zone than its parent.

How it works: the scope is a JSON object inside the credential subject. A
controller calls the check function with a proposed action and gets back whether
it is allowed plus a reason for each violated dimension. Delegation is governed
by an attenuation rule: a child scope is valid only if every numeric cap is less
than or equal to the parent, every allowed zone is a subset, and every shift
window fits inside some parent window.

The API: `build_physical_scope_credential`, `check_physical_action` (returns ok
plus reasons), and `attenuates(parent, child)` (the narrow-only guard). The check
and attenuation functions accept both native and JSON-decoded scope shapes, so a
scope issued in one language enforces identically in another.

Worked example (Go):

```go
scope := cred["credentialSubject"].(map[string]any)["physicalScope"].(map[string]any)
res := robotics.CheckPhysicalAction(scope, robotics.PhysicalAction{
    SpeedMps: ptr(1.5), NearHumans: true,   // rejected: near-humans cap is 0.5 m/s
})
// res.OK == false, res.Reasons == ["near_humans speed_exceeded: 1.5 m/s > 0.5 m/s"]
```

Security boundary: the runtime check rejects an action that exceeds any granted
dimension (an absent dimension is unconstrained by design). The attenuation check
is the privilege-escalation guard: a child that raises a cap, drops a cap the
parent set, adds a zone outside the parent set, or widens a window is rejected.

---

## 4. Robot-to-robot trust handshake

`vouch.robotics.handshake`

What it is: a three-message exchange (HELLO, ACCEPT, CONFIRM) by which two robots
in different trust domains authenticate each other and agree a bounded
cooperation session.

The problem it closes: when robots from different fleets meet and must cooperate,
each needs to know the other is who it claims and agree on a safe, limited set of
shared actions, without a central authority brokering it.

How it works: the initiator signs a HELLO proposing a scope and a fresh nonce.
The responder verifies the HELLO signature, checks the initiator's `did:web`
domain against its trust policy, and signs an ACCEPT whose `boundedScope` is the
intersection of the proposed scope and what the responder offers, never the
union. The initiator verifies the ACCEPT, confirms the nonce echoes its HELLO,
and signs a CONFIRM closing the session. Each message is an `eddsa-jcs-2022`
signed object, so authentication reuses the shared verifier.

The API: `build_hello`, `build_accept`, `verify_accept`, `build_confirm`,
`verify_confirm`, plus `TrustPolicy` (allow by domain, or accept unknowns
explicitly) and `BoundedSession`.

Security boundary: the responder signs an acceptance only if the HELLO signature
verifies and the initiator's domain passes the policy. The session scope is the
intersection of both offers, so neither side can widen the other's grant. The
nonce binds the acceptance to its HELLO, and a tampered message fails signature
verification.

---

## 5. Black box and kill switch

`vouch.robotics.blackbox`

Two related capabilities ship together.

The black box is an append-only, AES-256-GCM-encrypted, hash-linked flight
recorder. Each entry encrypts its payload under a 32-byte key; the encrypted blob
is `nonce(12) || ciphertext || tag(16)`, the same layout in every language. Each
entry also carries a `seq`, a `prevHash` linking to the previous entry, and an
`entryHash` over its own JCS-canonical body. The result has two independent
properties: the chain is tamper-evident without the key (any altered field breaks
its `entryHash`, any reordering breaks `prevHash`), and the payloads open only
with the key. An auditor can prove nothing was changed without being able to read
the contents; the key holder can read them.

The kill switch is a verifiable emergency stop. A `KillSwitchCredential` proves
who issued the stop, over what scope, and why. With an attested-authority
allowlist, verification rejects any issuer that is not on the list, so a rogue
actor cannot forge a legitimate-looking stop.

The API: `BlackBoxLog` (append, open, head, entries), `open_entry`,
`verify_blackbox_chain`, `genesis_prev_hash`, plus
`build_killswitch_credential` and `verify_killswitch_credential`.

Worked example (Python):

```python
log = blackbox.BlackBoxLog(key)                  # 32-byte AES key
entry = log.append("motion", {"speed": 1.5, "joint": "elbow"})
assert blackbox.verify_blackbox_chain(log.entries()).ok
payload = log.open_entry(entry)                  # only the key holder can read this
```

Security boundary: chain verification fails on a seq gap, a broken `prevHash`
link, or a recomputed `entryHash` that does not match (tampering). Decryption
fails under the wrong key. The kill switch fails on a wrong type, an invalid
proof, or, with an allowlist, an issuer that is not an attested authority.

---

## 6. Scannable robot passport

`vouch.robotics.passport`

What it is: a compact, signed `RobotPassport` encoded into a `vouch-passport:`
URI for a QR code or NFC tag, so anyone can check a robot's owner, authorized
actions, certification, and current standing offline, with no network call.

The problem it closes: a person standing in front of a robot needs to know it is
legitimate and what it is allowed to do, often with no connectivity. The passport
puts a verifiable summary on the robot itself.

How it works: the passport credential carries the robot's identity summary and a
`status` (active, suspended, or decommissioned). `encode_passport` serializes the
JCS-canonical credential into a deterministic multibase payload behind the
`vouch-passport:` scheme, so a scanner verifies the signature locally. The
encoding is deterministic, so a passport encoded in any language decodes and
verifies in the others.

The API: `build_passport`, `encode_passport`, `decode_passport`,
`verify_passport`, `verify_passport_uri`.

Security boundary: verification is fully offline (the verifier supplies the
issuer key). An expired passport fails. A suspended or decommissioned passport
still verifies but the status is surfaced, so a scanner refuses cooperation rather
than treating it as silently inactive. A tampered passport or a wrong type is
rejected.

---

## 7. Robot liveness heartbeat

`vouch.robotics.liveness`

What it is: a `RobotHeartbeatCredential` that a robot periodically self-signs,
carrying a "motion digest", aggregates of what it physically did over the
interval (peak force in newtons, peak speed in m/s, peak speed while a human was
near, and a count of zone breaches), plus whether it stayed inside the physical
envelope its `PhysicalCapabilityScope` permits.

The problem it closes: a static credential says a robot was trusted at issue
time, but a physical machine can drift, get damaged, or be tampered with between
heartbeats. This inverts "trusted until revoked" to "untrusted until renewed": a
verifier treats the robot as trusted only while a fresh AND in-envelope heartbeat
exists. It is the physical analogue of the agent Heartbeat Protocol and
behavioral attestation.

How it works: a `MotionCollector` records force, speed, near-human state, and
zone per sample over the interval and produces the digest, checked against the
robot's scope. The robot signs the digest into a heartbeat credential. A verifier
calls `is_live`, which combines freshness (the heartbeat is recent enough) with
conformance (the digest stayed inside the envelope). A heartbeat that is fresh but
out of envelope does not count as live.

The API: `MotionCollector` (records per-sample force/speed/near_humans/zone and
produces the digest), `build_robot_heartbeat`, `verify_robot_heartbeat`, `is_live`
(freshness plus conformance), and `validate_motion_digest`.

Security boundary: `is_live` fails if the heartbeat is stale or if the motion
digest fell outside the permitted envelope, so a robot that exceeded its force,
speed, near-human speed, or zone limits is not treated as live even with a
freshly signed heartbeat. Verification fails on a wrong type or an invalid proof.

---

## 8. Robot credential revocation

`vouch.robotics.revocation`

What it is: two levels of revocation for robots. Surgical per-credential
revocation attaches a `BitstringStatusList` `credentialStatus` entry to any robot
identity, provenance, or capability credential. Whole-DID revocation kills a
compromised key or a captured robot across all of its credentials at once.

The problem it closes: a single robot credential may need to be pulled (a stale
provenance attestation, a revoked capability) without touching the rest, while a
compromised key or a physically captured robot needs every credential under that
DID invalidated at once.

How it works: per-credential revocation reuses `vouch.status_list`. Attach a
status entry with `attach_credential_status` and check it with
`check_credential_status`. Whole-DID revocation reuses the existing
`vouch.revocation.RevocationRegistry`: a robot DID is an ordinary DID, so the
`.well-known` distribution path works unchanged. The registry is re-exported from
`vouch.robotics` for convenience.

The API: `attach_credential_status` and `check_credential_status` (per-credential,
over `vouch.status_list`), plus `RevocationRegistry` (whole-DID, re-exported from
`vouch.revocation`).

Security boundary: a verifier that checks `credentialStatus` rejects a credential
whose bit is set. A verifier that checks the revocation registry rejects every
credential under a revoked DID. The two levels are independent, so a deployment
can run both.

---

## 9. Accountable safety record

`vouch.robotics.safety_record`

What it is: an append-only, hash-linked, plaintext incident and near-miss ledger
(`SafetyEventLog`) of safety-relevant events (incident, near_miss,
manual_override, kill_switch, envelope_breach, maintenance), each with a severity
(info, low, medium, high, critical). A portable `RobotSafetyRecordCredential`
summarizes a stretch of the ledger into one signed artifact.

The problem it closes: a robot's safety history lives in scattered logs that do
not travel and cannot be trusted by an outside party. This gives the robot a
tamper-evident ledger plus a signed summary that travels with it across owners,
insurers, and regulators.

How it works: the ledger is plaintext (unlike the encrypted black box) but uses
the same hash-linked chain semantics, so it is tamper-evident: `verify_safety_log`
catches any altered or reordered entry. `summarize_entries` builds a summary over
a stretch of the ledger, counts by event type and by severity, the period
covered, and the ledger head hash that anchors the summary to the chain.
`build_safety_record` signs that summary into a portable credential and
`verify_safety_record` checks it. The summary reports plain counts.

The API: `SafetyEventLog` (append, entries, head), `verify_safety_log`,
`summarize_entries`, `build_safety_record`, and `verify_safety_record`.

Security boundary: log verification fails on any altered or reordered entry. The
safety-record credential fails on a wrong type or an invalid proof, and its head
hash ties the signed counts to a specific ledger state, so a summary cannot quietly
claim a cleaner history than the ledger it anchors to.

---

## 10. Perception provenance

`vouch.robotics.perception`

What it is: a signed record of the provenance of each captured sensor frame,
created at capture. Each record binds the frame's hash (multibase SHA-256), the
sensor id, the modality (camera, lidar, radar, depth, audio, thermal), the
capture time, and the robot's DID. The records are hash-linked into an
append-only `PerceptionLog`, so the sequence of what the robot perceived is
tamper-evident. The frames themselves are not stored, only their hashes.

The problem it closes: "what did the robot actually see, and in what order, when
it acted?" Raw sensor logs can be edited, reordered, or substituted after the
fact, and a frame can be swapped for one the robot never captured. Perception
provenance makes the captured stream cryptographic: every frame is bound to a
hash at capture, the order is fixed by the hash-link, and a verifier holding a
frame can confirm it is the one the robot recorded.

How it works: `hash_frame` computes the multibase SHA-256 of the raw frame
bytes. Each entry binds that hash to the sensor id, modality, capture time, and
robot DID, and links to the previous entry, so `verify_perception_log` catches
any altered or reordered entry. A `PerceptionProvenanceCredential`
(`build_perception_attestation`) attests a single frame, or a segment of the
stream via the log head, and `verify_perception_attestation` checks it. A
verifier that also holds the frame recomputes its hash to confirm it matches the
attested one.

The API: `hash_frame`, `PerceptionLog` (append, entries, head),
`verify_perception_log`, `build_perception_attestation`,
`verify_perception_attestation`, and `MODALITIES` (the allowed modality set:
camera, lidar, radar, depth, audio, thermal).

Worked example (Python):

```python
from vouch.robotics import perception

log = perception.PerceptionLog()
h = perception.hash_frame(frame_bytes)                         # multibase SHA-256
entry = log.append(sensor_id="cam-0", modality="camera", frame_hash=h, robot_did=robot_did)
assert perception.verify_perception_log(log.entries()).ok
att = perception.build_perception_attestation(robot_signer, log.head())
ok, subject = perception.verify_perception_attestation(att, robot_signer.public_key())
```

Security boundary: log verification fails on any altered or reordered entry. The
attestation fails on a wrong type or an invalid proof. A verifier holding the
frame and recomputing its hash detects a substituted frame, since the recomputed
hash no longer matches the attested one. Only hashes are recorded, so the log
proves what was perceived without retaining the frames themselves.

---

## 11. Delegation lease

`vouch.robotics.lease`

What it is: a short-lived, scope-bounded grant of authority that a robot can
verify and act on entirely offline, with no network call. An authority issues a
`DelegationLeaseCredential` bounding the robot's physical capability scope
(including allowed zones) for a fixed window. The robot verifies the signature,
that the window is current, and that a proposed action fits the scope.

The problem it closes: a robot often has to act where there is no connectivity
and no time to call home, yet handing it a long-lived broad grant is exactly the
authority you do not want a captured or malfunctioning machine to hold. A
delegation lease gives it just enough authority, for just long enough, and lets
it prove that authority on its own.

How it works: the lease credential carries a physical capability scope and a
validity window. The robot checks three things locally: the issuer signature
verifies, the current time falls inside the window, and the proposed action fits
within the scope (the same shrink-only physical scope check from capability 3).
Leases nest: each sub-grant attenuates the one above it, it never widens it,
which forms the open cross-vendor chain (a vendor leases to an integrator, the
integrator to an operator, the operator to the robot). Because every check is
local, the whole chain verifies with no network call.

The API: `build_delegation_lease`, `verify_delegation_lease`, and `lease_permits`
(does a proposed action fall inside a current, valid lease).

Worked example (Python):

```python
from vouch.robotics import lease

leased = lease.build_delegation_lease(
    operator_signer, robot_did,
    scope={"maxForceN": 10.0, "maxSpeedMps": 1.0, "allowedZones": ["dock-a"]},
    not_before=now, not_after=now + 3600,            # one-hour window
)
ok, scope = lease.verify_delegation_lease(leased, operator_signer.public_key(), now=now)
allowed = lease.lease_permits(leased, {"zone": "dock-a", "speedMps": 0.8}, now=now)
```

Security boundary: verification fails closed on a wrong type, an invalid
signature, a window that has not started or has expired, or a sub-lease that
widens any cap, adds a zone, or extends the window beyond its parent. A proposed
action outside the leased scope is refused locally, so a robot cannot act beyond
the authority it can prove, even with no connectivity.

---

## 12. Physical quorum

`vouch.robotics.physical_quorum`

What it is: a cryptographic two-person rule. A high-consequence physical action
is authorized only when at least M of an attested set of N approvers have each
signed an approval over the same action. The verifier counts distinct valid
approvers.

The problem it closes: some physical actions are consequential enough that no
single signer should be able to trigger them alone. A quorum makes the
"two-person rule" cryptographic: the authorization is only valid when enough
independent, attested approvers have each signed the very same action, so one
compromised key is not sufficient.

How it works: each approver signs an `ActionApproval` over the action
description. The verifier is given the action, the approval set, the attested
approver set (N), and the threshold (M). It checks every approval signature,
counts only distinct valid approvers drawn from the attested set, and authorizes
the action only when that count reaches M. Approvals over a different action, by
a signer outside the attested set, or duplicated from one approver, do not count
toward the threshold.

The API: `build_action_approval` (one approver signs the action) and
`verify_action_authorization` (counts distinct valid approvers against M of N).

Worked example (Python):

```python
from vouch.robotics import physical_quorum as quorum

action = {"action": "open_cell_gate", "zone": "cell-3", "robotDid": robot_did}
a1 = quorum.build_action_approval(approver_one, action)
a2 = quorum.build_action_approval(approver_two, action)
ok = quorum.verify_action_authorization(
    action, approvals=[a1, a2],
    approvers={approver_one_pub, approver_two_pub}, threshold=2,
)
```

Security boundary: authorization fails closed unless at least M distinct approvers
from the attested set have each signed the same action. An approval over a
different action, a signature from outside the attested set, an invalid proof, or
the same approver counted twice does not advance the count, so no single key and
no replayed approval can reach the threshold alone.

---

## 13. Robot lifecycle

`vouch.robotics.lifecycle`

What it is: the cryptographically accountable transitions a robot goes through
over its working life, ownership transfer, key rotation, and decommissioning,
each one a signed credential that a verifier can check. A robot outlives its
first owner, so each transition is made provable rather than assumed.

The problem it closes: a robot changes hands, rotates its key after a routine
schedule or a compromise, and is eventually retired, and each of those events
changes who should be trusted to act for it. Without signed transitions the
current owner, the current key, and the retired status are whatever a database
says. Lifecycle makes each transition a credential, so chain of custody, key
history, and retirement are all verifiable from the artifacts themselves.

How it works: ownership transfer is a `RobotOwnershipTransferCredential` the
current owner signs to a new owner, and linking each transfer to the previous one
forms a chain of custody that `verify_custody_chain` walks end to end. Key
rotation is a `RobotKeyRotationCredential` in which the robot's current key
authorizes a new key, forming a key history that `verify_key_history` walks, used
for a routine rotation or after a key compromise. Decommission is a
`RobotDecommissionCredential` an owner or authority signs to retire the robot,
after which a verifier should refuse to trust it.

The API: `build_ownership_transfer`, `verify_ownership_transfer`,
`verify_custody_chain`, `build_key_rotation`, `verify_key_rotation`,
`verify_key_history`, `build_decommission`, and `verify_decommission`.

Worked example (Python):

```python
from vouch.robotics import lifecycle

transfer = lifecycle.build_ownership_transfer(
    current_owner_signer, robot_did,
    new_owner="did:web:new-owner.example.com",
)
ok, subject = lifecycle.verify_ownership_transfer(transfer, current_owner_signer.public_key())
assert lifecycle.verify_custody_chain([transfer]).ok      # chain of custody
```

Security boundary: each transition verifies against the key that was authorized to
make it, the current owner for a transfer, the current key for a rotation, so a
forged transfer or an unauthorized key rotation fails. `verify_custody_chain` and
`verify_key_history` fail on a broken link, so a chain cannot skip or reorder a
transition. A verifier that sees a valid decommission refuses to trust the robot
thereafter. Verification fails closed on a wrong type or an invalid proof.

---

## 14. Regulatory conformance

`vouch.robotics.conformance`

What it is: a machine-checkable mapping from a robot's Vouch credentials to the
clauses of a public safety or AI regulation, called a conformance profile.
Built-in reference profiles cover ISO 10218-1/-2 (industrial robots), ISO/TS
15066 (collaborative operation, power and force limiting), the EU Machinery
Regulation 2023/1230, the EU AI Act high-risk requirements, and UL 3300 (service
and mobile robots). `check_conformance` runs a profile against a set of
credentials and returns a deterministic report; an issuer can sign a
point-in-time conformance attestation over that report.

The problem it closes: a robot may carry a hardware-rooted identity, a physical
scope, a safety record, and the rest, but "does this satisfy ISO 10218-1 or the
EU Machinery Regulation?" is still answered by hand, in a document, against
evidence nobody can independently recheck. A conformance profile turns that
mapping into something a verifier runs: each regulatory requirement is linked to
the credentials that satisfy it, and the answer is reproducible from the same
inputs.

How it works: a profile is an ordered list of requirements, each naming the
clause it maps to and the credential evidence it needs.
`check_conformance(credentials, profile_id)` walks the profile and, for each
requirement, decides whether the presented credentials satisfy it, citing the
clause. The report is deterministic: the same credentials and the same profile
produce the same report, and `report_digest` gives its multibase SHA-256 so it
can be referenced by hash. An issuer, the robot, its owner, or an assessing
authority, calls `build_conformance_attestation` to sign a point-in-time
`RobotConformanceAttestation` that embeds the report and binds it by digest;
`verify_conformance_attestation` checks the signature and that the embedded
report reproduces its bound digest. The profiles are a reference crosswalk that
makes conformance verifiable in the open. They are not legal advice, and a
deployment confirms each mapping against the current text of the regulation it
cites.

The API: `PROFILES` (the built-in reference profiles), `profile` (fetch one by
id), `check_conformance` (credentials plus a profile id to a deterministic
report), `report_digest`, `build_conformance_attestation`, and
`verify_conformance_attestation`. Credential type: `RobotConformanceAttestation`.

Worked example (Python):

```python
from vouch.robotics import conformance

report = conformance.check_conformance(credentials, profile_id="iso-10218-1")
for req in report.requirements:
    print(req.clause, req.satisfied)           # each clause cited, satisfied or not

att = conformance.build_conformance_attestation(authority_signer, report)
ok, subject = conformance.verify_conformance_attestation(att, authority_signer.public_key())
```

Security boundary: the report is deterministic, so anyone with the same
credentials and profile recomputes the same result and cannot be shown a
different answer. The attestation binds its report by digest, so the report
cannot be swapped after signing without breaking verification, and
`verify_conformance_attestation` fails closed on a wrong type, an invalid proof,
or a report that does not reproduce its bound digest. The profiles are a
reference crosswalk, not a legal ruling: a passing report attests that the cited
credentials satisfy the mapped clauses as the profile defines them, which a
deployment confirms against the regulation text.

---

## 15. Robotics post-quantum signing

`vouch.robotics.pq`

What it is: a post-quantum signing path for robot credentials. The credential
carries a Data Integrity proof set, an `eddsa-jcs-2022` proof and an
`mldsa44-jcs-2024` proof over the same document, and each proof verifies on its
own.

The problem it closes: a robot fielded today lives ten to twenty years, longer
than classical Ed25519 is expected to stay safe, so a robot identity signed now
could be forged once a quantum computer arrives. The proof set keeps the
classical guarantee for verifiers that only understand Ed25519 today and adds a
quantum-resistant guarantee that holds for the working life of the robot. This
makes the post-quantum profile the recommended default for robot credentials.

How it works: `sign_pq` attaches the proof set to a robot credential, so the
credential carries both proofs. Verification is backward compatible:
`verify_robot_credential` verifies a robot credential whether it carries a
classical proof or the proof set, auto-detected from the credential, so a fleet
can move to PQ gradually without breaking the classical credentials already in
the field. `verify_pq` verifies the proof set directly and needs the ML-DSA-44
public key, passed as raw bytes or a multikey. `is_pq` reports whether a
credential carries a post-quantum proof. `migrate_to_pq` re-signs a fielded
robot's classical credential under PQ, so a deployment can upgrade credentials
already in the field with a software re-sign rather than reissuing from scratch.

The API: `sign_pq`, `is_pq`, `verify_pq`, `verify_robot_credential`,
`migrate_to_pq`, and `HYBRID_CRYPTOSUITE`.

Security boundary: `verify_pq` fails closed on a wrong type, a missing or wrong
ML-DSA-44 public key, or either proof failing to verify, so a post-quantum
credential is accepted only when both the classical and the post-quantum proof
are valid. `verify_robot_credential` accepts a classical-only credential as
before and a post-quantum credential when both proofs verify, so migrating a
fleet to PQ never invalidates the classical credentials still in the field.
This is the open layer; managed PQ key custody and fleet-wide PQ migration orchestration are commercial.

---

## 16. Cross-embodiment identity continuity

`vouch.robotics.embodiment`

What it is: a way for one AI agent, a mind, to run on one robot body today and a
different body tomorrow while staying the same accountable identity. The agent is
a policy that holds its own persistent Vouch identity. An
`AgentEmbodimentCredential` binds that agent identity to a specific body (a
hardware-rooted robot identity) and that body's hardware root for a period, and
the agent signs the binding with its own key. Linking each embodiment to the one
before it (`fromBody`) forms a continuity chain.

The problem it closes: a fleet often runs one policy across many bodies over
time, a body is retired for maintenance and the mind moves to another, or a
long-lived agent outlives the machine it started on. Without a continuity record,
"is this the same accountable agent that acted last week, now in a different
body?" is answered by a database, and there is no way to prove the mind was not
quietly forked into two bodies acting at once. This makes the continuity of the
agent across bodies cryptographic: each move is a signed re-binding to a new
body's hardware root, and the chain proves one mind persisted rather than several
copies.

How it works: `build_embodiment` produces an `AgentEmbodimentCredential` in which
the agent's persistent key signs a binding of the agent identity to a body's
hardware-rooted robot identity, the body's hardware root, and a validity window,
with a `fromBody` link to the previous embodiment. `verify_embodiment` checks one
credential. `verify_continuity_chain` walks the linked chain end to end,
confirming each link is signed by the same persistent agent key and re-binds to
each body's hardware root, so the same accountable agent is shown to have
persisted across bodies. `check_no_fork` confirms the agent was never actively
embodied in two bodies at once, that no two embodiments have overlapping active
windows on different bodies. This is the inverse of the ownership custody chain in
lifecycle (13): there one body passes between owners, and the body is the
constant; here one mind passes between bodies, and the agent identity is the
constant that signs every link.

The API: `build_embodiment`, `verify_embodiment`, `verify_continuity_chain`, and
`check_no_fork`. Credential type: `AgentEmbodimentCredential`.

Worked example (Python):

```python
from vouch.robotics import embodiment

emb1 = embodiment.build_embodiment(
    agent_signer, body=body_a_identity,
    not_before=t0, not_after=t1,             # embodied in body A for this window
)
emb2 = embodiment.build_embodiment(
    agent_signer, body=body_b_identity,
    not_before=t2, not_after=t3, from_body=emb1,   # mind moves to body B
)
assert embodiment.verify_continuity_chain([emb1, emb2]).ok   # same agent across bodies
assert embodiment.check_no_fork([emb1, emb2]).ok             # never two bodies at once
```

Security boundary: verification fails closed on a wrong type, an invalid proof, or
a link signed by a different key than the persistent agent identity, so a chain
cannot splice in an embodiment signed by anyone but the agent itself.
`verify_continuity_chain` fails on a broken `fromBody` link, so the chain cannot
skip or reorder a body. `check_no_fork` fails when two embodiments claim
overlapping active windows on different bodies, so a forked mind acting in two
bodies at once is detectable. This is the open layer; managed key custody and
fleet migration are commercial.

---

## 17. Physical custody handoff

`vouch.robotics.custody`

What it is: a record of who physically held a task or object as it passes across
a chain of actors, human and robot. A person picks an item, hands it to a robot,
that robot hands it to another robot. Each handoff is a
`CustodyHandoffCredential` recording that a receiving actor accepted custody of a
task or object from a releasing actor, signed by the receiver, the party taking
responsibility for it next.

The problem it closes: when a physical task moves through several hands and
something goes wrong, damage, loss, a substituted item, "who had it when?" is
answered by paperwork that does not travel and cannot be trusted by an outside
party. Custody handoff makes the chain of physical possession cryptographic: each
transfer is a signed acceptance by the actor who took the thing, so a physical
incident traces to the exact hop and the exact actor responsible at that moment.

How it works: `build_handoff` produces a `CustodyHandoffCredential` in which the
receiver signs an acceptance of custody from a releasing actor (`fromActor`) to
itself (`toActor`), at a stated time, optionally recording a condition attested
at the moment of transfer. Linking each handoff so that each `toActor` becomes
the next `fromActor` forms a custody chain. `verify_handoff_chain` walks that
chain end to end to establish who held the task or object across every hop, and
`holder_at` returns who held it at a given time. When a condition is attested at
each handoff, `locate_condition_change` compares successive conditions and
localizes a physical state change (damage, loss) to the specific hop whose holder
was responsible for it. This is the physical counterpart of the accountability
chains elsewhere in the module: the ownership custody chain in lifecycle (13)
tracks who owns a body over its life, while custody handoff tracks who is holding
a task or object right now as it moves.

The API: `build_handoff`, `verify_handoff`, `verify_handoff_chain`, `holder_at`,
and `locate_condition_change`. Credential type: `CustodyHandoffCredential`.

Worked example (Python):

```python
from vouch.robotics import custody

h1 = custody.build_handoff(
    robot_a_signer, from_actor=person_did, to_actor=robot_a_did,
    task="deliver-parcel-42", at=t0, condition={"intact": True},
)
h2 = custody.build_handoff(
    robot_b_signer, from_actor=robot_a_did, to_actor=robot_b_did,
    task="deliver-parcel-42", at=t1, condition={"intact": True}, previous=h1,
)
assert custody.verify_handoff_chain([h1, h2]).ok       # who held it, each hop
holder = custody.holder_at([h1, h2], at=t1)             # actor holding it at t1
```

Security boundary: each handoff verifies against the receiver's key, the party
that accepted custody, so a handoff cannot be forged by anyone but the actor
taking responsibility. `verify_handoff_chain` fails on a broken link, so the
chain cannot skip or reorder a hop, and `holder_at` resolves the responsible
actor for any moment the chain covers. `locate_condition_change` pins a state
change to the hop whose holder was accountable for it. Verification fails closed
on a wrong type or an invalid proof. This is the open layer; managed logistics
custody orchestration and fleet tracking are commercial.

---

## 18. Robot-to-infrastructure bounded access

`vouch.robotics.access`

What it is: a way for a robot to open a door, call an elevator, dock at a
charger, or run a machine on authority an infrastructure operator granted it in
advance, checked at the resource with no network call. An infrastructure operator
(a warehouse, a hospital, a building) issues an operator-signed
`InfrastructureAccessGrant` naming a resource, the operations it permits, an
optional zone, and a time window. When the robot wants to act, it presents a
robot-signed `InfrastructureAccessRequest` for one operation on that resource, and
the resource authorizes it offline.

The problem it closes: a robot moving through a building needs to use fixed
infrastructure it does not own, and the resource has to decide, on its own,
whether this robot may perform this operation right now. Answering that with a
central access server means a network round trip on every door and every charger,
and a shared secret or a badge clone leaves no attributable record of who did
what. Robot-to-infrastructure bounded access makes the grant and the request
cryptographic: the resource checks operator and robot signatures locally, and the
grant plus the request is a tamper-evident record that attributes the action to
the exact robot and the exact grant that authorized it.

How it works: `build_access_grant` produces an `InfrastructureAccessGrant` in
which the operator signs a resource identifier, the permitted operations, an
optional zone, and a validity window. `build_access_request` produces a
robot-signed `InfrastructureAccessRequest` naming one operation on one resource at
a stated time. `authorize_access` runs the offline decision at the resource: the
grant must be valid and operator-signed, the request valid and robot-signed, the
requested operation must be one the grant permits, and the moment must fall inside
the window, so a resource authorizes only what its operator allowed. An operator
can issue a sub-grant that narrows an existing grant, and `attenuates_grant`
confirms a sub-grant only ever shrinks the operations, zone, or window it
inherits, never widens them, so authority attenuates down a chain the same way the
delegation lease (11) and the physical capability scope (3) attenuate.
`verify_access_grant` checks a grant on its own.

The API: `build_access_grant`, `verify_access_grant`, `build_access_request`,
`authorize_access`, and `attenuates_grant`. Credential types:
`InfrastructureAccessGrant`, `InfrastructureAccessRequest`.

Worked example (Python):

```python
from vouch.robotics import access

grant = access.build_access_grant(
    operator_signer, resource="dock-door-7", operations=["open", "close"],
    zone="bay-3", not_before=t0, not_after=t1,      # operator authorizes the robot
)
req = access.build_access_request(
    robot_signer, resource="dock-door-7", operation="open", at=t0,
)
assert access.authorize_access(grant, req, at=t0).ok    # resource decides offline
assert access.attenuates_grant(sub_grant, grant)        # a sub-grant only narrows
```

Security boundary: `authorize_access` fails closed on a wrong type, an invalid
operator or robot proof, an operation the grant does not permit, or a moment
outside the window, so a resource authorizes only an operation an operator signed
for and only while the grant is live. `attenuates_grant` fails when a sub-grant
adds an operation, widens the zone, or extends the window beyond what it inherits,
so a narrowed grant can never regain authority it was meant to drop. The grant and
the request together attribute every authorized action to the requesting robot and
the authorizing grant. This is the open layer; managed access orchestration and
fleet-wide grant issuance are commercial.

---

## 19. Fused-sensor provenance

`vouch.robotics.fusion`

What it is: a signed record of the provenance of a fused world model, created
when a robot combines many sensor frames into one output it acts on. Perception
provenance (10) signs individual frames; a robot fuses many of those frames
(camera, lidar, radar) into one world model, an object set, an occupancy grid, or
a pose, and acts on that. A `FusedPerceptionAttestation` binds the fused output's
hash to an ordered list of the input frame hashes, a digest over those inputs, and
a fusion method identifier, signed by the robot.

The problem it closes: "did the robot fuse exactly the frames it recorded into
exactly the output it acted on?" A fused world model is what a robot actually
plans and moves on, but the fusion step sits between the signed frames and the
action, so a manipulated fusion result, or a dropped or substituted input, would
otherwise leave no trace. Fused-sensor provenance makes the fusion step
cryptographic: the attestation commits to exactly those inputs and that output, and
each input can be checked against the robot's signed perception log to confirm
every fused input traces to a frame the robot actually recorded.

How it works: `hash_fused_output` computes the multibase SHA-256 of the raw fused
output bytes, and `fusion_inputs_digest` computes a digest over the ordered input
frame hashes. `build_fused_attestation` produces a `FusedPerceptionAttestation` in
which the robot signs the fused output hash, the ordered input hashes, that input
digest, and a fusion method identifier. `verify_fused_attestation` reproduces the
input digest and, with the raw output, its hash, so the attestation commits to
exactly those inputs and that output. `verify_fusion_inputs` checks each input
hash against the robot's signed perception log, so every fused input traces to a
frame the robot actually recorded, and a manipulated fusion result or a dropped or
substituted input is detectable.

The API: `hash_fused_output`, `fusion_inputs_digest`, `build_fused_attestation`,
`verify_fused_attestation`, and `verify_fusion_inputs`. Credential type:
`FusedPerceptionAttestation`.

Worked example (Python):

```python
from vouch.robotics import fusion

out_hash = fusion.hash_fused_output(world_model_bytes)          # multibase SHA-256
digest = fusion.fusion_inputs_digest([h_cam, h_lidar, h_radar]) # over ordered inputs
att = fusion.build_fused_attestation(
    robot_signer, output_hash=out_hash, input_hashes=[h_cam, h_lidar, h_radar],
    inputs_digest=digest, method="occupancy-grid-v1",
)
assert fusion.verify_fused_attestation(att, robot_signer.public_key(), world_model_bytes).ok
assert fusion.verify_fusion_inputs(att, log.entries()).ok       # inputs trace to the log
```

Security boundary: `verify_fused_attestation` reproduces the input digest and the
output hash, so it fails on a wrong type, an invalid proof, an altered output, or a
changed or reordered input list, and the attestation therefore commits to exactly
the inputs and the output it was signed over. `verify_fusion_inputs` fails when a
fused input has no matching entry in the robot's signed perception log, so a
dropped or substituted input is detectable and every fused input traces to a frame
the robot actually recorded. Hardware sensor attestation and managed sensor-fusion
orchestration are commercial.

---

## 20. Wear and degradation attestation

`vouch.robotics.wear`

What it is: a signed record in which a robot attests its own degradation as a
normalized wear level (0 for as-new, 1 for fully worn), with optional detailed
metrics (actuator wear, calibration drift, cycle count, fault rate), bound to its
identity and hash-linked to the previous attestation by its proof so the wear
history is tamper-evident over time. A deterministic rule, `attenuate_for_wear`,
derives a physical capability scope whose numeric caps are scaled down by the wear
level, and the result is a valid attenuation (3) of the original scope.

The problem it closes: "does a robot still operate inside the envelope its
condition warrants, not the one it shipped with?" A robot's actuators, sensors, and
calibration drift as it ages, but a static factory limit does not move, so a worn
robot keeps its original authority even as its safe operating margin shrinks. Wear
and degradation attestation makes the robot's own condition a signed, tamper-evident
input to its authority: the wear history cannot be silently rewritten, and the
narrowed scope is provably a subset of the original.

How it works: `build_wear_attestation` produces a wear attestation in which the
robot signs its normalized wear level and any detailed metrics, linking to the
previous attestation by that attestation's proof, so the records form a
hash-linked chain. `verify_wear_attestation` checks a single attestation's proof
against the robot's identity, and `verify_wear_chain` walks the linked attestations
so a rewritten or dropped record is detectable. `attenuate_for_wear` takes the
original physical capability scope and the wear level and returns a scope whose
numeric caps are scaled down by that level, and because it only lowers caps the
result satisfies `attenuates(original, worn)`, so a worn robot runs inside a
tighter, verifiable envelope derived from its own signed condition.

The API: `build_wear_attestation`, `verify_wear_attestation`, `verify_wear_chain`,
and `attenuate_for_wear`. Credential type: `WearAttestation`.

Worked example (Python):

```python
from vouch.robotics import wear

att = wear.build_wear_attestation(
    robot_signer, wear_level=0.4,
    metrics={"actuator_wear": 0.5, "calibration_drift": 0.3, "cycle_count": 120000},
    previous=prior_att,                                     # hash-links to the prior
)
assert wear.verify_wear_attestation(att, robot_signer.public_key()).ok
assert wear.verify_wear_chain([prior_att, att]).ok         # tamper-evident history
worn_scope = wear.attenuate_for_wear(original_scope, att)  # caps scaled by wear level
```

Security boundary: `verify_wear_attestation` fails on a wrong type, an invalid
proof, or an attestation that does not link to the previous one, and
`verify_wear_chain` fails when a record in the history is rewritten or dropped, so
the wear history is tamper-evident and bound to the robot's identity.
`attenuate_for_wear` only scales caps down, so its result is a valid attenuation of
the original scope and a worn robot operates inside a tighter, verifiable envelope.
Firmware-level enforcement of the narrowed envelope and managed
predictive-maintenance modeling are commercial.

---

## 21. Bystander-consent evidence

`vouch.robotics.consent`

What it is: a robot working in a shared or public space captures people
incidentally, and this records, at capture time, the basis on which a capture was
permitted, bound to the specific capture (by its hash, reusing the perception
capture hash) and to the robot's identity, holding only hashes and never an image
or a bystander's identifying data. A bystander (or their device) can sign a
`BystanderConsentToken` bound to that one capture hash and the robot, so the
consent verifies only against the capture it was given for and cannot be replayed
to a different recording. A `BystanderConsentEvidence` credential is signed by the
robot, binding the capture to a consent basis (explicit consent, posted notice,
legitimate interest, or a redaction that was applied) and, for explicit consent,
to the tokens that cover it, referenced by their proof value so no identifying data
is embedded.

The problem it closes: "on what basis did a robot capture the people around it,
and can that be shown after the fact without keeping anyone's biometrics?" A robot
in a shared space records people it never enrolled, and a plain log either keeps
identifying data it should not hold or proves nothing about why the capture was
allowed. Bystander-consent evidence makes the permission basis a signed artifact
bound to the exact capture and the robot: consent is provable, tied to one
recording, and stored as hashes and a basis rather than images or identities.

How it works: `hash_capture` computes the capture hash (the same hash the
perception log uses). `build_consent_token` lets a bystander sign a
`BystanderConsentToken` over that capture hash and the robot's DID, so the token is
bound to one capture and one robot, and `verify_consent_token` checks the
bystander's proof, the binding, and the window, so a token cannot be replayed to a
different recording. `build_consent_evidence` lets the robot sign a
`BystanderConsentEvidence` credential binding the capture hash to a basis from
`CONSENT_BASES`, and for explicit consent it commits to the covering tokens by
their proof value, never embedding identifying data. `verify_consent_evidence`
checks the robot's proof and the accepted basis, reproduces the capture hash when
the capture is supplied, and, when tokens and bystander keys are supplied, confirms
every token verifies, is bound to this capture and this robot, and matches a
committed reference, so an explicit-consent evidence is backed by real tokens for
exactly that capture.

The API: `hash_capture`, `build_consent_token`, `verify_consent_token`,
`build_consent_evidence`, and `verify_consent_evidence`. Credential types:
`BystanderConsentEvidence` and `BystanderConsentToken`. Accepted bases:
`CONSENT_BASES` (explicit consent, posted notice, legitimate interest, redacted).

Worked example (Python):

```python
from vouch.robotics import consent

cap_hash = consent.hash_capture(frame_bytes)                 # reuses the capture hash
token = consent.build_consent_token(                         # bystander signs, bound to one capture
    bystander_signer, bystander_did=bystander_did,
    capture_hash=cap_hash, robot_did=robot_did,
)
evidence = consent.build_consent_evidence(                   # robot signs the basis for this capture
    robot_signer, robot_did=robot_did, capture_hash=cap_hash,
    basis="explicit-consent", consent_tokens=[token],        # committed by proof value, no PII
)
ok, subject = consent.verify_consent_evidence(
    evidence, robot_signer.public_key(),
    capture=frame_bytes, consent_tokens=[token],
    bystander_keys={bystander_did: bystander_signer.public_key()},
)
assert ok                                                    # basis backed by a token for this capture
```

Security boundary: `verify_consent_token` fails on a wrong type, an invalid proof,
a token bound to a different capture or robot, or an expired token, and
`verify_consent_evidence` fails on a wrong type, an invalid proof, an unaccepted
basis, a capture whose hash does not match, an explicit-consent evidence with no
tokens, or any supplied token that does not verify or does not match a committed
reference, so consent is bound to one capture, tied to the robot's identity, and
cannot be replayed. Only hashes and a basis are stored, never an image or a
bystander's identifying data, so the evidence is verifiable without retaining
anyone's biometrics. On-device biometric detection and redaction, and managed
consent-registry orchestration, are commercial.

---

## How they compose

A real deployment chains them: a robot has a hardware-rooted identity (1),
carries a signed record of the exact model and policy it runs (2), enforces
physical limits before every move (3), negotiates bounded cooperation with robots
it meets (4), records an encrypted tamper-evident log and honors a verifiable
kill switch (5), presents a scannable passport anyone can check offline (6), keeps
proving it is live and in-envelope with self-signed heartbeats (7), can have any
one credential or its whole DID revoked (8), carries a tamper-evident safety
record that travels with it (9), signs the provenance of every sensor frame
it captures (10), acts on a short-lived offline delegation lease that attenuates
down a cross-vendor chain (11), gates its highest-consequence actions behind
a physical quorum (12), carries cryptographically accountable lifecycle
transitions as it changes owners, rotates keys, and is retired (13), maps its
credentials to the clauses of a public safety or AI regulation with a signed
conformance report (14), can sign those robot credentials with a post-quantum
proof set so an identity issued today still holds once quantum computers arrive
(15), and carries the same agent identity from one body to the next along a
signed continuity chain that proves one mind persisted across bodies without ever
running in two at once (16), records a signed custody chain as a physical task
or object passes from hand to hand so an incident traces to the exact hop and
actor who held it (17), and acts on operator-signed grants to open a door or dock
at a charger, authorized offline at the resource with an attributable record of
which robot did what (18), and signs the provenance of a fused world model so the
frames it combined and the output it acted on are exactly what it committed to,
each fused input tracing back to a frame it recorded (19), and attests its own
wear as a signed, hash-linked history from which a tighter physical capability
scope is derived, so a worn robot operates inside a narrower verifiable envelope
than the one it shipped with (20), and records, at capture time, the basis on
which it captured the people around it, binding that basis to the exact capture and
to its own identity while holding only hashes so consent is provable without
retaining anyone's biometrics (21). Every artifact is the same Verifiable
Credential format, so one verifier and one trust model cover all twenty-one.

## Quick answers

- Can a robot prove which hardware it is? Yes, hardware-rooted identity (1).
- Can I prove what model and safety policy ran, even after an OTA update? Yes,
  the re-signable provenance attestation (2).
- Can I enforce that a robot slows near people or stays in its zone? Yes, the
  physical capability scope, checked before actuation (3).
- Can two robots from different fleets cooperate safely? Yes, the bounded-trust
  handshake (4).
- Can I prove who hit the emergency stop and stop anyone else from doing it? Yes,
  the kill-switch credential with an attested-authority allowlist (5).
- Can a robot keep a flight recorder that is private but tamper-evident? Yes, the
  encrypted black box (5).
- Can someone scan a robot to check it is legitimate, offline? Yes, the scannable
  passport (6).
- Can a robot keep proving it is still trustworthy while running, beyond its
  issue time? Yes, the liveness heartbeat, fresh plus in-envelope (7).
- Can I revoke one robot credential, or kill a compromised or captured robot
  outright? Yes, per-credential status plus whole-DID revocation (8).
- Can a robot carry a tamper-evident safety record across owners, insurers, and
  regulators? Yes, the accountable safety record (9).
- Can a robot prove what it actually perceived, and in what order, when it acted?
  Yes, perception provenance: a hash-linked log of signed frame records, with a
  frame holder able to recompute the hash and confirm it (10).
- Can a robot act on delegated authority offline, with no network call? Yes, a
  short-lived scope-bounded delegation lease it verifies and checks locally,
  attenuating down a cross-vendor chain (11).
- Can I require more than one approver before a high-consequence physical action?
  Yes, a physical quorum: M of N attested approvers must each sign the same
  action (12).
- Can I prove who owns a robot now, that its key history is sound, and that a
  retired robot is no longer trusted? Yes, robot lifecycle: signed ownership
  transfers forming a chain of custody, a key rotation history, and a
  decommission credential a verifier honors by refusing to trust the robot (13).
- Can I check a robot's credentials against a safety or AI regulation and get a
  signed result? Yes, regulatory conformance: machine-checkable reference
  profiles (ISO 10218, ISO/TS 15066, the EU Machinery Regulation, the EU AI Act,
  UL 3300) that produce a deterministic report `check_conformance` builds and
  `build_conformance_attestation` signs, citing the clause each requirement maps
  to (14).
- Will a robot identity signed today still be safe once quantum computers
  arrive? Yes, robotics post-quantum signing: an Ed25519 proof and an
  ML-DSA-44 proof on the same credential, with verification that auto-detects a
  classical credential or a proof set so a fleet migrates gradually without
  breaking credentials already in the field (15).
- Can one agent run on one robot body today and a different body tomorrow and
  still be the same accountable identity? Yes, cross-embodiment identity
  continuity: an embodiment credential binds the agent to a body's hardware root
  for a window, a continuity chain `verify_continuity_chain` walks proves the same
  agent persisted across bodies, and `check_no_fork` confirms it was never
  embodied in two bodies at once (16).
- Can I trace who physically held a task or object as it passed from a person to
  a robot to another robot? Yes, physical custody handoff: each transfer is a
  receiver-signed `CustodyHandoffCredential`, `verify_handoff_chain` walks the
  chain to show who held it at each hop, `holder_at` returns the holder at a given
  time, and `locate_condition_change` pins damage or loss to the responsible hop
  (17).
- Can a robot open a door, call an elevator, or dock at a charger it does not own,
  decided offline at the resource? Yes, robot-to-infrastructure bounded access: an
  operator signs an `InfrastructureAccessGrant` naming a resource, operations, an
  optional zone, and a window, the robot presents a signed
  `InfrastructureAccessRequest`, and `authorize_access` decides at the resource
  with no network call, while `attenuates_grant` keeps every sub-grant narrowing
  only (18).
- Can a robot prove it fused exactly the sensor frames it recorded into the world
  model it acted on? Yes, fused-sensor provenance: a `FusedPerceptionAttestation`
  binds the fused output's hash to the ordered input frame hashes and a fusion
  method, `verify_fused_attestation` reproduces the input digest and the output
  hash so the attestation commits to exactly those inputs and that output, and
  `verify_fusion_inputs` traces every fused input back to a frame in the robot's
  signed perception log (19).
- Can a robot narrow its own authority as it wears out, instead of keeping a static
  factory limit? Yes, wear and degradation attestation: the robot signs its wear
  level (0 as-new to 1 fully worn) with optional metrics into a hash-linked
  history `verify_wear_chain` checks, and `attenuate_for_wear` derives a physical
  capability scope whose caps are scaled down by that wear level, a valid
  attenuation of the original so the robot runs inside a tighter verifiable
  envelope (20).
- Can a robot show on what basis it captured the people around it, without keeping
  their biometrics? Yes, bystander-consent evidence: the robot records a consent
  basis (explicit consent, posted notice, legitimate interest, or redacted) in a
  `BystanderConsentEvidence` credential bound to the exact capture hash and its own
  identity, a bystander can sign a `BystanderConsentToken` bound to that one capture
  so it cannot be replayed, and `verify_consent_evidence` confirms the basis (and,
  for explicit consent, the covering tokens) while only hashes are ever stored (21).

## Status

All twenty-one capabilities are implemented and tested in Python, TypeScript, Go, and
the Rust core, with the Rust core flowing to the Swift, Kotlin/JVM, .NET, C/C++,
and WebAssembly wrappers. A runnable demo lives in `examples/robotics_demo.py`,
the canonical write-up in `docs/robotics.md`, and a shared interop vector pins the
hardware-root binding and the config hash. The liveness heartbeat builds on the
agent Heartbeat Protocol, the revocation paths reuse `vouch.status_list` and
`vouch.revocation`, the safety record reuses the black-box chain semantics,
perception provenance reuses the same hash-linked log semantics, and the
conformance profiles map robotics credentials to the clauses of public safety and
AI regulations as an open reference crosswalk.
The novel methods are published as open defensive disclosures: PAD-064
(hardware-rooted identity), PAD-067 (robot-to-robot handshake), PAD-069
(confidential tamper-evident black box), and PAD-070 (scannable offline passport).

## From the wrapper SDKs (C, C++, .NET, JVM, Swift)

The reference SDKs (Python, TypeScript, Go, and the Rust core) carry the full
robotics surface. The C, C++, .NET, JVM (Java and Kotlin), and Swift wrappers
expose a curated consumer surface over the same core, the same way they expose the
agent operations: a `VouchRobotics` class in .NET, JVM, and Swift, and a
`vouch::robotics` namespace in C++. The curated surface is what an application
verifies and integrates with:

- `verify_robot_credential`: verify a robot credential whether it carries a
  classical proof or a post-quantum proof set, auto-detected from the credential.
- `mint_identity` and `verify_identity` for a hardware-rooted robot identity.
- `check_conformance` with `build_conformance_attestation` and
  `verify_conformance_attestation` for regulatory conformance.
- `verify_passport` for an offline passport scan.
- `check_action` to enforce a physical capability scope.
- `sign_pq` to attach a post-quantum proof set.
- `authorize_access` to decide an infrastructure access request offline against an
  operator grant.
- `verify_fused_attestation` for fused-sensor provenance, and
  `verify_continuity_chain` for cross-embodiment identity continuity.
- `verify_wear_attestation` with `attenuate_for_wear` for wear and the narrowed
  capability scope.
- `verify_consent_evidence` for bystander-consent evidence.
- `verify_handoff_chain` for a physical custody chain.

Output is byte-identical to the reference SDKs, so a robot credential produced in
one language verifies in every other. The producer-side operations (handshakes,
the black box, physical quorum, the liveness heartbeat) stay in the reference SDKs;
a wrapper application that needs one of those calls a reference SDK or a service
built on it. Example, verifying a robot credential from .NET:

```csharp
using VouchProtocol.Core;

bool ok = VouchRobotics.VerifyRobotCredential(credentialJson, ed25519PublicB64);
string report = VouchRobotics.CheckConformance(credentialsJson, "eu-ai-act-high-risk");
```
