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

What it is: a hybrid post-quantum signing path for robot credentials. A hybrid
proof carries a classical Ed25519 signature alongside an ML-DSA-44 signature
under one cryptosuite, `hybrid-eddsa-mldsa44-jcs-2026`.

The problem it closes: a robot fielded today lives ten to twenty years, longer
than classical Ed25519 is expected to stay safe, so a robot identity signed now
could be forged once a quantum computer arrives. Signing robot credentials with a
hybrid proof keeps the classical guarantee for verifiers that only understand
Ed25519 today and adds a quantum-resistant guarantee that holds for the working
life of the robot. This makes the hybrid cryptosuite the recommended default for
robot credentials.

How it works: `sign_pq` attaches a hybrid proof to a robot credential, so the
credential carries both signatures. Verification is backward compatible:
`verify_robot_credential` verifies a robot credential whether it carries a
classical or a hybrid proof, auto-detected from the proof, so a fleet can move to
PQ gradually without breaking the classical credentials already in the field.
`verify_pq` verifies a hybrid proof directly and needs the ML-DSA-44 public key,
passed as raw bytes or a multikey. `is_pq` reports whether a credential is
hybrid-signed. `migrate_to_pq` re-signs a fielded robot's classical credential
under PQ, so a deployment can upgrade credentials already in the field with a
software re-sign rather than reissuing from scratch.

The API: `sign_pq`, `is_pq`, `verify_pq`, `verify_robot_credential`,
`migrate_to_pq`, and `HYBRID_CRYPTOSUITE`.

Security boundary: `verify_pq` fails closed on a wrong type, a missing or wrong
ML-DSA-44 public key, or either signature failing to verify, so a hybrid proof is
accepted only when both the classical and the post-quantum signature are valid.
`verify_robot_credential` accepts a classical-only credential as before and a
hybrid credential when both signatures verify, so migrating a fleet to PQ never
invalidates the classical credentials still in the field. This is the open layer;
managed PQ key custody and fleet-wide PQ migration orchestration are commercial.

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
conformance report (14), and can sign those robot credentials with a hybrid
post-quantum proof so an identity issued today still holds once quantum computers
arrive (15). Every artifact is the same Verifiable Credential format, so one
verifier and one trust model cover all fifteen.

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
  arrive? Yes, robotics post-quantum signing: a hybrid Ed25519 and ML-DSA-44
  proof, with verification that auto-detects classical or hybrid so a fleet
  migrates gradually without breaking credentials already in the field (15).

## Status

All fifteen capabilities are implemented and tested in Python, TypeScript, Go, and
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
