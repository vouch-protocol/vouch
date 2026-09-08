# AAT ↔ Vouch Protocol interop

**Attenuating Authorization Tokens** ([`draft-niyikiza-oauth-attenuating-agent-tokens-01`](https://datatracker.ietf.org/doc/html/draft-niyikiza-oauth-attenuating-agent-tokens-01))
are JWT-based delegation tokens for AI agents, profiling RFC 9396 Rich
Authorization Requests. An AAT names the tools an agent may invoke and the
argument constraints on those invocations; any holder can derive a narrower
token offline, with no authorization-server round trip, and the resulting chain
verifies against its root trust anchor. This adapter verifies such a chain,
turns the leaf's authority into Vouch Shield rules, enforces them **before** an
MCP tool call runs, and links the resulting Vouch credential back to the AAT
that authorised the action.

**Same invariant, two envelopes.** AAT and Vouch's delegation model both enforce
that authority may only narrow - never widen - as it is handed on. AAT expresses
that in OAuth/RAR form as a signed token chain; Vouch expresses it as a
Verifiable Credential chain over six dimensions (action, target, resource, time,
rate, policy). Neither had to change to work with the other: AAT is an *input*
to the gate, and Vouch's credential format, cryptosuite and Shield semantics are
untouched. The two compose - OAuth-world delegation underneath, VC-world
accountability on top.

Chain verification and token derivation are **not** reimplemented here. Both are
delegated to the AAT reference implementation
([`tenuo`](https://github.com/tenuo-ai/tenuo), Apache-2.0), which the draft's
Implementation Status appendix names. This adapter is the layer between that and
Vouch.

## Install and run

```bash
pip install tenuo
python3 -m pytest integrations/aat/tests/ -q
```

Run from the repository root. `integrations/` is not part of the installed
`vouch` package (the same is true of `integrations/ros2/`), so set
`PYTHONPATH=/path/to/vouch-protocol` when invoking it from elsewhere.

Try it:

```python
from integrations.aat import AatGate, verify_chain_file

chain = verify_chain_file("test-vectors/aat/valid-narrowing-chain.json")
gate = AatGate(chain, holder_key=holder_key)

decision = gate.check("read_file", {"path": "reports/q3.txt"})
if decision.allowed:
    run_the_tool()          # only ever reached on an allowed decision
```

With `vouch-mcp`:

```bash
vouch-mcp --aat-chain leaf.json --aat-holder-key holder.pem
```

That exposes a `check_action_aat` tool which sources its rules from the chain's
leaf. **Precedence:** when a static allow-list is also in force, both must allow.
An AAT chain narrows what the server will do; it never widens it. If the chain
is missing or fails to verify, the tool denies - there is no lax fallback.

**Where enforcement actually binds.** `AatGate.check` is the enforcement API:
it returns a decision and never executes anything, so a caller that runs a tool
only on `decision.allowed` cannot execute an unauthorised call. That is the
in-process path, and it is what the tests assert against with a mock tool.

`check_action_aat` is a *decision* tool in the same shape as the existing
`check_action`: it answers ALLOW or DENY and does not itself run the gated tool.
Over MCP the decision therefore binds only as far as the client honours it,
exactly as `check_action` does today. This adapter deliberately did not change
that, since Shield semantics were out of scope. If you need enforcement that
cannot be bypassed by a client, put `AatGate` in front of the tool in-process
rather than relying on the MCP decision tool.

See [`DEMO.md`](DEMO.md) for the recordable walkthrough and
[`DESIGN.md`](DESIGN.md) for the full mapping.

## What maps cleanly

| AAT | Vouch | |
|---|---|---|
| Tool name | Shield `action` | Exact string match on both sides, no normalization |
| Narrow-only derivation | Attenuation MUST-rule | The same invariant |
| `jti` | `intent.authorizedBy` on the credential | Records which delegation authorised the action |
| Leaf `exp` | Credential validity window | Clamped, so a credential never outlives its authority |

## What does not map cleanly

This list is a deliverable, not a caveat section. Full detail in
[`DESIGN.md`](DESIGN.md) §5.1.

1. **Shield cannot express AAT argument constraints.** Its permission check is
   `check_permission(did, tool)` - it never sees the call's arguments, and its
   rule model is per-DID capability *levels*, not per-argument predicates.
   Flattening AAT constraints into those levels would silently widen authority:
   a leaf limited to `reports/*` would become a blanket filesystem-read grant
   and `read_file /etc/passwd` would pass. So this adapter does not flatten
   them. Tool scope becomes Shield rules; argument constraints stay with the
   reference implementation and are evaluated in the same pre-execution step.
   Both must allow.

2. **Vouch's `rate` and `policy` dimensions have no AAT equivalent** in the core
   constraint set. Carrying them would need registered extension constraint
   types (draft §3.5).

3. **The demo's own constraint is not a core AAT type.** Path globbing
   (`reports/*`) is explicitly excluded from the draft's core nine and deferred
   to a registered extension - §3.5.3 uses "Path Containment" as its worked
   example. It is real in the reference implementation, not yet registered in
   the draft.

4. **PoP and VC holder binding are different guarantees.** AAT's
   proof-of-possession is per-invocation and covers the arguments; a Vouch
   credential attests an action issued by a DID. The adapter records the
   PoP-verified `jti` on the credential; it does not claim the credential is
   itself a proof of possession.

5. **Depth ceilings do not round-trip.** AAT requires an explicit
   `del_max_depth`; Vouch imposes no fixed depth limit. AAT → Vouch is safe;
   the reverse would mean inventing a ceiling.

6. **Identifier schemes differ.** A derived AAT's `iss` is a JWK-thumbprint URN;
   Vouch uses DIDs. `did:key` is the nearest analogue and neither spec defines
   the conversion.

7. **Wire format.** The draft's normative envelope is JWT/JWS. The reference
   implementation is CBOR/COSE-native and its Appendix E says so plainly
   ("implementation-specific ... does not define a fully interoperable CWT
   profile"). There is therefore no shipping implementation of the draft's
   encoding to test against. This adapter works against the *protocol model* -
   the attenuation invariants and chain verification of §4, §6 and §7 - through
   the author's own implementation. The fixtures in `test-vectors/aat/` are CBOR
   warrant chains, and are labelled as such. **This adapter does not consume
   draft-format AAT JWTs**, and nothing here should be read as claiming it does.

## Layout

| File | Purpose |
|---|---|
| `aat_chain.py` | Load a chain, verify it against its root anchor, return a verified chain or a typed failure |
| `aat_to_shield.py` | Leaf authority → Shield rules; the pre-execution gate |
| `credential_link.py` | Record the authorising AAT on the issued credential |
| `demo_setup.py`, `demo_call.py` | Scene 4 |
| `tests/` | 17 tests, each named for what it proves |
| `../../test-vectors/aat/` | Chain fixtures and their generator |

Failures are typed so a caller can branch on them: `AatMalformedChain`,
`AatBadSignature`, `AatBrokenChain`, `AatWidenedScope`, `AatExpired`,
`AatUntrustedRoot`, `AatPopMismatch`, all under `AatError`. Every path is
fail-closed - a failure yields no rules and nothing executes.

Implementer feedback on the draft is in
[`../../INTEROP-NOTES.md`](../../INTEROP-NOTES.md).

## Licence

Apache-2.0, matching the rest of the repository and the reference
implementation.
