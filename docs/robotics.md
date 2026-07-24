# Vouch Robotics Primitives

Open, vendor-neutral formats and reference implementations for accountable robots
and embodied agents. All are eddsa-jcs-2022 credentials or hash-linked formats
built on the existing Vouch primitives, so they verify with the cross-language
SDKs. These are formats plus references; hosted storage and fleet-scale services
are out of scope.

The examples below are in Python, but all six capabilities are implemented in
Python (`vouch.robotics`), TypeScript (`packages/sdk-ts/src/robotics`), Go
(`go-sidecar/robotics`), and the Rust core (`core/vouch-core`, module `robotics`),
which flows to the Swift, Kotlin/JVM, .NET, C/C++, and WebAssembly wrappers. A
robotics credential signed in any language verifies in every other, pinned by
`test-vectors/robotics/vector.json`.

## 5.1 Hardware-rooted robot identity (`vouch.robotics.identity`)

A `RobotIdentityCredential` binds a robot's software identity key to a hardware
root of trust (a TPM or a secure element). The hardware root signs a binding over
the robot DID and key, embedded as `hardwareRoot.attestation`; a verifier checks
both the credential proof and the hardware attestation.

```python
from vouch.robotics import SoftwareRootOfTrust, mint_robot_identity, verify_robot_identity

root = SoftwareRootOfTrust(kind="TPM")          # reference; a TPM/secure-element backend subclasses HardwareRootOfTrust
cred = mint_robot_identity(robot_signer, root, make="Acme", model="AR-7", serial="SN-123")
ok, subject = verify_robot_identity(cred, robot_public_key)
```

`HardwareRootOfTrust` is the interface a TPM- or secure-element-backed
implementation satisfies (it signs with a hardware-resident attestation key).
`SoftwareRootOfTrust` is the development reference and is NOT a hardware root.
`lifecycle` records the make/commission/transfer/decommission history.

## 5.2 Model and config provenance (`vouch.robotics.provenance`)

A `ModelProvenanceAttestation` records the VLA model name, weights hash, safety
policy, and config hash running on a robot. It is re-signable on an OTA update,
referencing the attestation it `supersedes`, forming a tamper-evident chain.

```python
from vouch.robotics import build_provenance_attestation, verify_provenance_attestation

att = build_provenance_attestation(builder_signer, robot_did=robot,
        model_name="OpenVLA-7B", weights_hash="u...", safety_policy="u...",
        config=runtime_config, version="2.1.0", supersedes=prev_id)
ok, subject = verify_provenance_attestation(att, builder_public_key, config=runtime_config)
```

`configHash` is the multibase SHA-256 of the JCS-canonical config, reproducible
in any language.

## 5.3 Physical capability scope (`vouch.robotics.capability`)

Extends the capability/attenuation model to the physical world: max force, max
speed, a slower speed cap near humans, allowed zones, and shift windows, carried
in a `PhysicalCapabilityScope` credential and enforceable before actuation.

```python
from vouch.robotics import build_physical_scope_credential, check_physical_action, PhysicalAction, attenuates

cred = build_physical_scope_credential(operator_signer, subject_did=robot,
        max_force_n=100, max_speed_mps=2.0, max_speed_near_humans_mps=0.5,
        allowed_zones=["zone-A"], shift_windows=[{"start": "08:00", "end": "18:00"}])
scope = cred["credentialSubject"]["physicalScope"]
decision = check_physical_action(scope, PhysicalAction(force_n=50, speed_mps=1.5,
        near_humans=True, zone="zone-A", time_hm="10:00"))
# A delegated scope must attenuate (never broaden):
assert attenuates(parent_scope, child_scope)
```

## 5.4 Robot-to-robot trust handshake (`vouch.robotics.handshake`)

Two robots in different trust domains authenticate and establish a bounded-trust
session before cooperating, via three signed messages (HELLO, ACCEPT, CONFIRM).
The responder checks the initiator's domain against its `TrustPolicy` and
intersects the proposed scope with what it offers, so the session scope is never
broader than what either side grants.

```python
from vouch.robotics import build_hello, build_accept, verify_accept, build_confirm, verify_confirm, TrustPolicy

hello = build_hello(robot_a_signer, proposed_scope=["lift", "carry"])
accept = build_accept(robot_b_signer, hello=hello, hello_public_key=a_pub,
                      policy=TrustPolicy(trusted_domains={"robot-a.example.com"}),
                      offered_scope=["carry", "weld"])
ok, session = verify_accept(accept, b_pub, expected_nonce=hello["nonce"])   # session.scope == ["carry"]
confirm = build_confirm(robot_a_signer, session=session)
verify_confirm(confirm, a_pub, session_id=session.session_id, expected_nonce=session.nonce)
```

## 5.5 Black box and kill switch (`vouch.robotics.blackbox`)

The black box is an append-only, AES-256-GCM-encrypted, hash-linked flight
recorder: payloads are confidential, the chain is tamper-evident without the key,
and the head can be signed to anchor the log. The kill-switch credential is a
verifiable emergency-stop record; with an authority allowlist, only an attested
authority can trigger it.

```python
from vouch.robotics import BlackBoxLog, open_entry, verify_blackbox_chain
from vouch.robotics import build_killswitch_credential, verify_killswitch_credential

log = BlackBoxLog(key=os.urandom(32))
log.append("FAULT", {"code": "E12"})
ok, _ = verify_blackbox_chain(log.entries())        # verifiable without the key
payload = open_entry(log.entries()[0], key)          # only the key opens the payload

stop = build_killswitch_credential(authority_signer, target=robot_did, reason="human in path")
ok, subject = verify_killswitch_credential(stop, authority_pub, trusted_authorities={authority_did})
```

## 5.6 Scannable robot passport (`vouch.robotics.passport`)

A compact, signed passport that anyone can scan (QR or NFC) to check a robot's
owner, authorized actions, certification, and standing, offline. The QR/NFC
payload is a `vouch-passport:` URI carrying the multibase JCS bytes of the
credential, so the reader verifies the signature without a network call.

```python
from vouch.robotics import build_passport, encode_passport, verify_passport

passport = build_passport(robot_signer, robot_did=robot, make="Acme", model="AR-7",
                          owner=owner_did, authorized_actions=["carry", "scan"],
                          certification="CE-2026-001", status="active")
uri = encode_passport(passport)                      # put this in a QR or NFC tag
ok, summary = verify_passport(uri, robot_public_key) # offline check of owner/actions/standing
```

Interop vector: `test-vectors/robotics/vector.json` pins the hardware-root binding
and the config hash. See `examples/robotics_demo.py`.

## 5.7 Living trust heartbeat (`vouch.robotics.liveness`)

Robot trust is otherwise minted once and valid until revoked. The heartbeat makes
it living: the robot periodically self-signs a `RobotHeartbeatCredential` carrying
a motion digest (peak force, peak speed, peak speed near humans, and a count of
zone breaches over the interval) plus whether it stayed inside its
`PhysicalCapabilityScope`. A verifier treats the robot as trusted only while a
fresh and in-envelope heartbeat exists, inverting "trusted until revoked" to
"untrusted until renewed".

```python
from vouch.robotics import MotionCollector, build_robot_heartbeat, is_live

col = MotionCollector(scope=scope["physicalScope"])
col.record(force_n=12.0, speed_mps=0.4, near_humans=True, zone="cell-3")
hb = build_robot_heartbeat(robot_signer, session_id="sess-1", interval_index=0,
                           motion_digest=col.digest(), interval_seconds=30)
live = is_live(hb)                                    # fresh AND in-envelope
```

## 5.8 Credential revocation (`vouch.robotics.revocation`)

Two-level revocation for robot credentials. Surgical per-credential revocation
attaches a BitstringStatusList entry to an identity, provenance, or capability
credential (`attach_credential_status` / `check_credential_status`). Whole-DID
kill, for a leaked key or a captured robot, uses the existing `RevocationRegistry`
(a robot DID is an ordinary DID, so the `.well-known` distribution path is
unchanged).

```python
from vouch.robotics import attach_credential_status, check_credential_status

cred = attach_credential_status(scope_cred, robot_signer,
    status_list_credential="https://fleet.example/status/1", status_list_index=42)
revoked = check_credential_status(cred, status_list_cred)
```

## 5.9 Accountable safety record (`vouch.robotics.safety_record`)

An append-only, hash-linked, plaintext ledger of safety events (incident,
near-miss, manual override, kill-switch trigger, envelope breach) with a severity,
plus a portable `RobotSafetyRecordCredential` that summarizes the ledger into
counts by event type and severity, the period, and the ledger head hash that
anchors it. The summary cannot understate the log without breaking the chain.

```python
from vouch.robotics import SafetyEventLog, build_safety_record, verify_safety_log

log = SafetyEventLog()
log.append("near_miss", severity="low")
log.append("envelope_breach", severity="high")
ok, _ = verify_safety_log(log.entries())             # tamper-evident
record = build_safety_record(authority_signer, robot_did=robot, summary=log.summarize())
```

## 5.10 Perception provenance (`vouch.robotics.perception`)

A robot signs the provenance of each captured sensor frame at capture: a record
binding the frame's hash, the sensor id, the modality (camera, lidar, radar,
depth, audio, thermal), the capture time, and the robot's DID. Records hash-link
into an append-only `PerceptionLog`, so the sequence of what the robot perceived
is tamper-evident, and a `PerceptionProvenanceCredential` attests a frame (or a
segment, via the log head). Only frame hashes are stored, never the raw frames; a
verifier holding the frame recomputes its hash to confirm it.

```python
from vouch.robotics import PerceptionLog, build_perception_attestation, hash_frame

log = PerceptionLog()
entry = log.record(sensor_id="cam-front", modality="camera", frame=frame_bytes)
att = build_perception_attestation(robot_signer, robot_did=robot, sensor_id="cam-front",
                                   modality="camera", frame_hash=entry["frameHash"],
                                   log_head=log.head())
```

## 5.11 Offline delegation lease (`vouch.robotics.lease`)

A short-lived, scope-bounded grant of authority a robot can verify and act on
entirely offline, for places with no connectivity. An authority issues a
`DelegationLeaseCredential` bounding the robot's physical capability scope
(including zones) for a fixed window; the robot verifies the signature, that the
window is current, and that a proposed action fits the scope, with no network
call. Leases nest, each sub-grant only narrowing the one above, which forms the
open cross-vendor chain.

```python
from vouch.robotics import build_delegation_lease, verify_delegation_lease, lease_permits

lease = build_delegation_lease(authority_signer, robot_did=robot, lease_id="shift-42",
                               scope={"maxForceN": 80.0, "allowedZones": ["cell-3"]},
                               valid_seconds=3600)
ok, subject = verify_delegation_lease(lease, authority_signer.public_key())   # offline
```

## 5.12 Physical quorum (`vouch.robotics.physical_quorum`)

A cryptographic two-person rule: a high-consequence physical action is authorized
only when at least M of an attested set of N approvers have each signed an
approval over the same action. `verify_action_authorization` counts the distinct
valid approvers, so one approver cannot reach the threshold by signing twice.

```python
from vouch.robotics import build_action_approval, verify_action_authorization

approvals = [build_action_approval(a, action_id="weld-7", robot_did=robot) for a in approvers]
authorized, who = verify_action_authorization(approvals, action_id="weld-7", robot_did=robot,
                                              approver_keys=approver_keys, threshold=2)
```

## 5.13 Lifecycle and decommissioning (`vouch.robotics.lifecycle`)

A robot outlives its first owner, so its transitions are made cryptographically
accountable. The current owner signs an ownership transfer to a new owner, and
linking each transfer forms a chain of custody (`verify_custody_chain`). The
robot's current key authorizes a successor, forming a key history
(`verify_key_history`), for a routine rotation or after a compromise. An owner or
authority signs a decommission credential retiring the robot, after which a
verifier should refuse to trust it.

```python
from vouch.robotics import build_ownership_transfer, build_key_rotation, build_decommission

transfer = build_ownership_transfer(seller_signer, robot_did=robot, to_owner=buyer_did)
rotation = build_key_rotation(robot_signer, robot_did=robot, new_key_multibase=new_key)
retired = build_decommission(authority_signer, robot_did=robot, reason="end of service life",
                            final_disposition="recycled")
```

## 5.14 Regulatory conformance (`vouch.robotics.conformance`)

A conformance profile is a machine-checkable mapping from a robot's credentials to
the clauses of a public safety or AI regulation. Built-in reference profiles cover
ISO 10218-1/-2, ISO/TS 15066, the EU Machinery Regulation 2023/1230, the EU AI Act
high-risk requirements, and UL 3300. `check_conformance` walks a profile and
reports, per requirement, whether the presented credentials satisfy it, citing the
clause. An assessing party signs a point-in-time attestation over that report.

```python
from vouch.robotics import check_conformance, build_conformance_attestation

report = check_conformance([identity, provenance, scope, safety_record], "eu-ai-act-high-risk")
attestation = build_conformance_attestation(assessor, robot_did=robot, report=report)
```

The report is deterministic, so every language reproduces it from the same
credentials, and the attestation binds the embedded report by digest. The profiles
are a reference crosswalk, not legal advice; a deployment confirms each mapping
against the current regulation text for its market.

## 5.15 Post-quantum signing (`vouch.robotics.pq`)

A robot fielded today runs for ten to twenty years, longer than classical Ed25519
is expected to stay safe, so robot credentials carry a Data Integrity proof set,
an `eddsa-jcs-2022` proof and an `mldsa44-jcs-2024` proof over the same document.
Each proof verifies on its own and both must verify for the credential to be
accepted. `verify_robot_credential` verifies a credential whether it carries a
classical proof or the proof set, detected from the credential, so a fleet moves
to post-quantum without breaking the credentials already in the field. `migrate_to_pq` re-signs a fielded robot's classical credential under a
post-quantum key.

```python
from vouch.robotics import sign_pq, verify_robot_credential, mint_robot_identity

identity = sign_pq(mint_robot_identity(robot, root, make="Acme", model="AR-7", serial="SN-1"), robot)
ok = verify_robot_credential(identity, robot_ed25519_public_key,
                             mldsa44_public_key=robot.public_key_mldsa44_multikey())
```

A hybrid credential passes only when both signatures validate, so it is at least as
strong as the classical signature and stays safe once classical signatures do not.

## 5.16 Cross-embodiment identity continuity (`vouch.robotics.embodiment`)

An AI agent (a mind with its own Vouch identity) can run on one robot body today and
a different body tomorrow. An embodiment credential binds the agent to a body and
that body's hardware root for a period, signed by the agent's own key.
`verify_continuity_chain` walks a sequence of embodiments, confirms every one is
signed by the same agent key and that each `fromBody` matches the previous `body`,
and returns the current body, so a verifier confirms the same accountable agent
persisted across bodies. `check_no_fork` confirms no two embodiments place the agent
in different bodies with overlapping active windows. This is the inverse of the
ownership custody chain: there one body passes between owners, here one mind passes
between bodies.

```python
from vouch.robotics import build_embodiment, verify_continuity_chain, check_no_fork

a = build_embodiment(agent, agent_did=agent_did, body_did="body-a", body_hardware_root="uA", valid_seconds=3600)
b = build_embodiment(agent, agent_did=agent_did, body_did="body-b", body_hardware_root="uB", from_body="body-a")
ok, current_body = verify_continuity_chain([a, b], agent_public_key)
no_fork, _ = check_no_fork([a, b])
```

The open layer is signed credentials and software verification; managed key custody
and fleet migration are commercial.

## 5.17 Physical custody handoff (`vouch.robotics.custody`)

A physical task or object passes across a chain of actors, human and robot. A
`CustodyHandoffCredential` records that a receiving actor accepted custody of the
task from a releasing actor, signed by the receiver. `verify_handoff_chain` walks a
sequence of handoffs (each receiver becomes the next releaser) and returns the
current holder, and `holder_at` returns who held the task at a given time, so a
physical-world incident traces to the exact hop and actor. A condition attested at
each handoff lets `locate_condition_change` localize a physical state change to the
holder responsible for it.

```python
from vouch.robotics import build_handoff, verify_handoff_chain, holder_at, locate_condition_change

h1 = build_handoff(robot_a, task_id="tote-42", from_actor=picker_did, to_actor=robot_a_did, condition="intact")
h2 = build_handoff(robot_b, task_id="tote-42", from_actor=robot_a_did, to_actor=robot_b_did, condition="damaged")
ok, current_holder = verify_handoff_chain([h1, h2], {robot_a_did: a_key, robot_b_did: b_key})
change = locate_condition_change([h1, h2])
```

The open layer is signed handoff credentials and software verification; managed
logistics custody orchestration and fleet tracking are commercial.

## 5.18 Infrastructure access (`vouch.robotics.access`)

A robot in a warehouse, hospital, or building needs to open doors, call elevators,
dock at chargers, and operate machines. An infrastructure operator signs an
`InfrastructureAccessGrant` naming the resource, the permitted operations, an
optional zone, and a time window. The robot signs an `InfrastructureAccessRequest`
for one operation on one resource. The resource runs `authorize_access` offline and
allows the operation only when the grant verifies under the operator key and is in
window, the request verifies under the robot key, the grant and request name the
same robot and resource, and the operation is permitted. The grant plus the request
is a tamper-evident, attributable record of the access, and `attenuates_grant`
confirms a sub-grant only narrows what it inherits.

```python
from vouch.robotics import build_access_grant, build_access_request, authorize_access

grant = build_access_grant(operator, robot_did=robot_did, resource="door-3", operations=["open", "close"], zone="cell-3", valid_seconds=3600)
request = build_access_request(robot, robot_did=robot_did, resource="door-3", operation="open")
result = authorize_access(grant, request, operator_key, robot_key)
```

The open layer is signed grants and requests, offline authorization, and shrink-only
attenuation; hardware-enforced actuation at the resource and managed fleet
access-policy orchestration are commercial.

## 5.19 Fused-sensor provenance (`vouch.robotics.fusion`)

Perception provenance signs individual sensor frames. A robot fuses many frames from
cameras, lidar, and radar into a single world model, an object set, an occupancy grid,
or a pose, and acts on that. `build_fused_attestation` signs a
`FusedPerceptionAttestation` binding the fused output's hash to an ordered list of the
input frame hashes, a digest over those inputs, and a fusion method identifier.
`verify_fused_attestation` checks the robot's proof, reproduces the input digest so the
attestation commits to exactly those inputs, and, given the raw fused output,
reproduces its hash. `verify_fusion_inputs` checks each named input against the robot's
signed perception log and returns any that were never recorded, so a manipulated fusion
result or a dropped or substituted input is detectable.

```python
from vouch.robotics import build_fused_attestation, verify_fused_attestation, verify_fusion_inputs, hash_frame

inputs = [hash_frame(cam), hash_frame(lidar), hash_frame(radar)]
att = build_fused_attestation(robot, robot_did=robot_did, fusion_method="occupancy-grid-v1", input_frame_hashes=inputs, fused_output=world_model)
ok, subject = verify_fused_attestation(att, robot_key, fused_output=world_model)
inputs_ok, missing = verify_fusion_inputs(att, perception_log.entries())
```

The open layer is software-signed provenance reusing the perception frame hashes;
hardware sensor attestation and managed sensor-fusion orchestration are commercial.

## 5.20 Wear and degradation (`vouch.robotics.wear`)

A robot does not stay as capable as it left the factory: actuators wear, sensors
drift, and error rates creep up. `build_wear_attestation` signs a
`RobotWearAttestation` carrying a normalized wear level (0 for as-new, 1 for fully
worn) and optional metrics, bound to the robot's identity. Each attestation links to
the previous one by its proof, so `verify_wear_chain` walks a tamper-evident wear
history. `attenuate_for_wear` derives a physical scope whose numeric caps are scaled
by (1 - wear level), and the result is a valid attenuation of the original scope, so
the same attenuation check the rest of Vouch uses carries the derating.

```python
from vouch.robotics import build_wear_attestation, verify_wear_chain, attenuate_for_wear

w1 = build_wear_attestation(robot, robot_did=robot_did, wear_level=0.1)
w2 = build_wear_attestation(robot, robot_did=robot_did, wear_level=0.3, prev_proof=w1["proof"]["proofValue"])
ok, latest = verify_wear_chain([w1, w2], robot_key)
narrowed = attenuate_for_wear(full_scope, latest["wearLevel"])
```

The open layer is the signed wear state and the derived narrowed scope credential;
firmware-level enforcement of the narrowed envelope and managed predictive-maintenance
modeling are commercial.

## 5.21 Bystander consent (`vouch.robotics.consent`)

A robot in a shared or public space captures people incidentally. `build_consent_token`
has a bystander sign over the hash of one capture and the robot's DID, so
`verify_consent_token` accepts it only for that capture and that robot and it cannot be
replayed to another recording. `build_consent_evidence` has the robot bind the capture
hash to a consent basis, one of `CONSENT_BASES` (explicit-consent, posted-notice,
legitimate-interest, or redacted), and for explicit consent it commits to the covering
tokens by their proof value. `verify_consent_evidence` checks the robot's proof, that the
basis is accepted, and, when given the raw capture, that its hash matches. Only hashes
and the basis are stored, never an image or a bystander's identifying data.

```python
from vouch.robotics import hash_capture, build_consent_token, build_consent_evidence, verify_consent_evidence

ch = hash_capture(frame)
token = build_consent_token(person, bystander_did=person_did, capture_hash=ch, robot_did=robot_did, valid_seconds=3600)
ev = build_consent_evidence(robot, robot_did=robot_did, capture_hash=ch, basis="explicit-consent", consent_tokens=[token])
ok, subject = verify_consent_evidence(ev, robot_key, capture=frame, consent_tokens=[token], bystander_keys={person_did: person_key})
```

The open layer is the cryptographic binding of a consent basis to a capture and its
verification, holding only hashes; on-device biometric detection and redaction, and
managed consent-registry orchestration, are commercial.

Sections 5.7 to 5.21 are implemented in Python, TypeScript, Go, and the Rust core
(which flows to the Swift, Kotlin/JVM, .NET, C/C++, and WebAssembly wrappers),
byte-identical and pinned by `test-vectors/robotics/vector.json`.
