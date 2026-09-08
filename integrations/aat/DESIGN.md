# AAT ↔ Vouch interop - design

Status: **accepted and implemented.** Scoping decisions recorded in Section 9.

This document is Step 0 of the AAT interop work: what the AAT draft says, what
the reference implementation actually ships, and how AAT concepts map onto Vouch
Shield rules and the Vouch Signer's per-action credential.

The claim this work is meant to make true:

> AAT and Vouch's delegation model enforce the same narrow-only invariant - AAT
> in OAuth/RAR form, Vouch as a VC - and they compose.

Nothing here asserts precedence, origin, or priority for either project. This is
an interop exercise.

---

## 1. Source documents

| Thing | Where | Notes |
|---|---|---|
| The draft | `draft-niyikiza-oauth-attenuating-agent-tokens-01` | Published 15 June 2026, expires 17 December 2026. 3,696 lines. Author: Niki Aimable Niyikiza (Tenuo). |
| Text used | `https://www.ietf.org/archive/id/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` | Read in full. |
| Reference implementation | `https://github.com/tenuo-ai/tenuo` | **Apache-2.0.** Rust core, Python bindings. |
| Python distribution | PyPI `tenuo`, version 0.2.4 | `License: Apache-2.0`, `Requires-Python: >=3.9`. Prebuilt `abi3` wheels for linux/macOS/Windows. |

Both licence and language check out: Apache-2.0 matches Vouch's own licence, and
the Python bindings are directly callable. **The stop-and-report condition in the
brief does not trigger.** We depend on the reference implementation for
derivation and chain verification and do not reimplement either.

---

## 2. What the draft specifies

### 2.1 Claim set (§3.2, Table 1)

Common claims on every AAT:

| Claim | Presence | Meaning |
|---|---|---|
| `jti` | REQUIRED | Unique token identifier. UUIDv7 RECOMMENDED. |
| `iss` | REQUIRED | Root tokens: issuer URI. Derived tokens: `urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>` of the parent holder key. |
| `iat`, `exp` | REQUIRED | Issuance and expiry. |
| `cnf` | REQUIRED | Confirmation object carrying the holder's public key (`jwk`). |
| `del_depth` | REQUIRED | Position in the chain. Root is 0; each derivation adds exactly 1. |
| `del_max_depth` | REQUIRED | Absolute ceiling. Monotonically non-increasing down the chain. |
| `par_hash` | Root: MUST be absent. Derived: MUST be present. | Base64url SHA-256 of the parent's JWS Signing Input. |
| `authorization_details` | REQUIRED | RFC 9396 array carrying the tool capability claims. |

Ed25519 signing MUST be supported. JCS (RFC 8785) is used for canonicalization.

### 2.2 Tools and argument constraints (§3.3, §3.4)

`authorization_details` entries are typed `attenuating_agent_token` and carry a
`tools` object:

```json
{
  "type": "attenuating_agent_token",
  "tools": {
    "read_file": { "path": { "constraint_type": "exact", "value": "reports/q3.txt" } }
  }
}
```

Tool identifiers match by **exact string**, with no normalization (§3.3.1).

Nine core constraint types are normative (§3.4, Table 2). Both the `check`
predicate and the `subsumes` relation are normative - two implementations MUST
agree:

`exact`, `range` (with `min`/`max` and inclusivity flags), `one_of`,
`not_one_of`, `contains`, `subset`, `wildcard`, `all` (AND), `any` (OR).

Two fail-closed rules matter for us:

- An enforcement point **MUST deny** if it meets a `constraint_type` it does not
  recognize.
- An enforcement point **MUST ignore** unrecognized *top-level JWT claims* - a
  token must not be rejected merely for carrying extra claims.

Anything richer than the core nine (path containment, URI normalization, policy
expressions) MUST be a **registered extension constraint type** (§3.5). §3.5.3
gives "Path Containment" as the worked example of such a registration.

### 2.3 Derivation: "equal or narrower" (§6)

A derived token MUST satisfy all of:

- **Tools**: a subset of the parent's tool set.
- **Per-tool constraints**: same argument keys as the parent where the parent's
  set is non-empty; each constraint subsumed by the parent's per §4.5.
- **`exp`**: less than or equal to the parent's.
- **`iat`**: greater than or equal to the parent's.
- **`del_depth`**: exactly parent + 1.
- **`del_max_depth`**: at least the child's own depth, at most the parent's ceiling.

Derivation is entirely offline. No authorization-server round trip.

### 2.4 Chain verification (§7)

Seven steps, root anchor down to leaf:

1. Chain size and cycle checks.
2. Root token validation: algorithm, signature, claims, exactly one AAT entry.
3. Adjacent-pair checks against the five invariants - **I1** delegation
   authority, **I2** depth monotonicity, **I3** TTL monotonicity, **I4**
   capability monotonicity, **I5** `par_hash` cryptographic linkage.
4. Chain length consistency.
5. Leaf: tool present, constraints evaluated in closed-world mode.
6. PoP JWT verification.

All offline.

### 2.5 Proof of possession (§5)

A separate PoP JWT per invocation, signed by the key matching the leaf's
`cnf.jwk`, carrying: fresh `jti`, `iat`, `aat_id` (the leaf's `jti`), `aat_tool`
(exact tool name), optional `aat_aud`, and `hta` (the tool arguments,
JCS-canonicalized). This is invariant **I6**.

### 2.6 Implementation Status (Appendix E)

Quoted in relevant part:

> Tenuo provides a reference implementation of this protocol. The chain
> verification algorithm (Section 7) and token derivation procedure (Section 6)
> are both implemented. Tenuo also includes an implementation-specific CBOR/COSE
> wire representation, with Ed25519 signatures carried in COSE_Sign1 structures.
> That implementation experience supports the format independence of the core
> protocol model, but does not define a fully interoperable CWT profile; the CWT
> profile is deferred as described in Appendix D.

Appendix E gives **no repository URL and no licence**. Both were found by search
and confirmed against PyPI and the repository's `LICENSE` file. That gap is
logged in `INTEROP-NOTES.md`.

---

## 3. The finding that shapes this work: two wire formats

The draft's normative envelope is **JWT/JWS**. The shipped reference
implementation is **CBOR/COSE-native**.

Verified directly against `tenuo` 0.2.4:

```
Warrant.to_bytes()[:5] == b'\x83\x01\x58\xa6\xaa'   # CBOR: array(3), uint(1), bytes(0xa6), map(6)
```

There is no `Warrant.from_jwt` / `to_jwt` on the 0.2.4 Python surface. The
vocabulary differs too: the library says *warrant*, *capability*, *holder*; the
draft says *AAT*, `authorization_details`, `cnf`.

Appendix E is candid that the CBOR/COSE representation is implementation-specific
and does not constitute an interoperable profile. So there is no shipping
implementation of the draft's JWT wire format to test against - the author's own
implementation realises the draft's *protocol model*, not its *encoding*.

This forces an explicit scoping choice, because the brief forbids reimplementing
chain verification:

- **What we can do**: verify chains, derive narrower tokens offline, and extract
  leaf authority using the reference implementation - i.e. exercise the exact
  normative model of §4, §6 and §7 through the author's code.
- **What we cannot do without reimplementing the spec**: produce or verify
  draft-conformant JWT AATs. Writing a JWT AAT encoder plus verifier *is* the
  thing the brief rules out.

**Recommended resolution.** Build the adapter against the reference
implementation's protocol model. Fixtures under `test-vectors/aat/` are then
tenuo CBOR warrant chains, and we say so plainly in the README rather than
implying they are draft-encoded JWTs. The interop claim stays true and precise:
*the attenuation invariant composes*, demonstrated through the draft author's own
implementation. The claim we must **not** make is "Vouch consumes draft-format
AAT JWTs" - that would be false today, for anyone.

Optionally we can render a verified leaf's effective authority into the draft's
`authorization_details` JSON shape for display and for the credential link. That
is a presentation mapping only, with no cryptographic meaning, and it must be
labelled as such wherever it appears.

---

## 4. The Vouch side

### 4.1 Shield

`vouch/shield/shield.py`. The pre-execution gate is:

```python
Shield.intercept(tool: str, args: dict, token: str|None, did: str|None) -> InterceptResult
```

Four steps: signature check → trust status → `PermissionManager.check_permission(did, tool)` → allow.

The rule model (`vouch/shield/permissions.py`) is **coarse and per-DID**:
`Capabilities(filesystem, network, shell, custom)` at levels
`none < read < write < full`, plus a module-level `TOOL_REQUIREMENTS` map from
tool name to required levels.

The consequence that drives the design: **Shield's permission check takes `tool`
but never `args`.** It cannot express a per-argument constraint. AAT's whole
expressive core is per-argument constraints.

### 4.2 Vouch's own delegation attenuation

`vouch/attenuation.py` - `non_expansion(parent, child)` over six dimensions:
`action`, `target`, `resource` (sub-resource containment), `time` (window
nesting), `rate` (events/sec), `policy` (no-weaker). Default-deny on any
malformed or ambiguous input. This is the same narrow-only invariant as AAT's
I4/I3, over a different dimension set.

### 4.3 The Signer

`Signer.sign(intent=..., action=, target=, resource=, ...) -> dict`.

`intent` is validated only for the presence of `action`, `target`, `resource`
(`vouch/vc.py::_validate_intent`) and is then placed **verbatim** into
`credentialSubject.intent`. Extra keys survive into the credential and are
covered by the Data Integrity proof.

That is our extension point for the credential link. No new required field, no
change to the credential format, no change to the cryptosuite.

---

## 5. Mapping table

| AAT concept | Vouch concept | Mapping | Lossy? |
|---|---|---|---|
| Tool name (`tools` key, exact-match) | Shield `action` / the `tool` argument to `intercept` | Direct 1:1, byte-exact string. Both sides already match tool names exactly with no normalization. | **No** |
| Argument constraints (`{arg: {constraint_type, …}}`) | Shield `resource` glob | **Exact for path-shaped constraints.** Shield v2 matches `action`/`target`/`resource` with globs, so `Pattern`, `Exact` and `OneOf` over paths become real Shield rules and Shield refuses an out-of-scope path itself. Non-path forms (`Range`, `Regex`, `CEL`, `Cidr`, `Not`, …) have no Shield equivalent and stay with the reference implementation's evaluator. Both gates must allow either way. | **No** for path-shaped; **yes** otherwise - see 5.1 |
| Chain parent reference (`par_hash`) | Delegation parent `id` | Both bind a child to exactly one parent instance. AAT binds by SHA-256 of the parent's signing input; Vouch binds by parent credential `id` plus proof binding. Provenance-equivalent, not byte-equivalent. | **Yes - representation only** |
| Narrow-only derivation (§6, I4) | Attenuation MUST-rule (`non_expansion`) | Identical invariant: a child may only narrow. Different dimension sets (AAT: tools + per-arg constraints + exp + depth; Vouch: action/target/resource/time/rate/policy). | **No** (invariant), **yes** (dimensions - see 5.1) |
| `jti` | External authorisation reference on the credential | Carried as `intent.authorizedBy` - an extra key inside the existing `intent` dict, covered by the proof. Records *which delegation authorised this action*. | **No** |
| `exp` / TTL monotonicity (I3) | Credential validity window (`validFrom`/`validUntil`) | Leaf `exp` clamps the issued credential's validity so the credential never outlives the authority that justified it. | **No** |
| `cnf` / PoP (I6) | Holder binding | AAT binds per-invocation via a PoP signature over (leaf id, tool, JCS args). Vouch binds the credential to the issuer DID's key. Related but not the same object: PoP proves *this call*, the VC proves *this issuer*. | **Yes - see 5.1** |
| `del_depth` / `del_max_depth` | Chain depth | Vouch imposes no fixed depth limit; AAT requires an explicit ceiling. Mapping AAT→Vouch is safe (a bound maps into the unbounded case); Vouch→AAT would need a ceiling invented. | **Yes - one direction only** |
| `iss` (JWK-thumbprint URN on derived tokens) | Issuer DID | Different identifier schemes. A thumbprint URN is not a DID; `did:key` is the closest analogue and the conversion is not defined by either spec. | **Yes** |

### 5.1 Lossy rows, stated plainly

This list is a deliverable in its own right.

1. **Path-shaped argument constraints now map exactly; other shapes do not.**
   This row used to read "Shield cannot express AAT argument constraints",
   because Shield's rule model was per-DID capability *levels* and its check
   never saw a call's arguments. Shield v2 matches `action`/`target`/`resource`
   with globs on `resource`, so a leaf's `Pattern("reports/*")` becomes a real
   Shield rule and Shield refuses `read_file /etc/passwd` on its own.

   Two cautions remain. First, the two glob languages differ: Tenuo's `*`
   crosses `/` and Shield's does not, so patterns are **translated**, not
   copied, and a differential test asserts the Shield rule is never wider than
   the constraint it came from. Second, constraint forms with no faithful
   translation (`Range`, `Regex`, `CEL`, `Cidr`, `Not`, `NotOneOf`, mid-string
   `*`) fall back to `resource: "**"` and remain the reference implementation's
   responsibility alone. Shield never *replaces* that evaluator; it adds a
   second, independent refusal point for the subset it can express. Both must
   allow.

2. **The reverse direction is lossy too.** Vouch's `rate` and `policy`
   dimensions have no AAT equivalent in the core constraint set. AAT would need
   registered extension constraint types (§3.5) to carry them.

3. **`Pattern("reports/*")` is not a core AAT constraint type.** The demo's
   natural constraint is path-globbing, which the draft explicitly excludes from
   the core nine and defers to a registered extension (§3.5.3, "Path
   Containment"). So the demo exercises a constraint that is real in the
   reference implementation but not yet registered in the draft. Worth flagging
   to the author.

4. **PoP and VC holder binding are not the same guarantee.** AAT's PoP is
   per-invocation and covers the arguments. A Vouch credential attests an issued
   action by a DID. The adapter records the PoP-verified `jti` in the credential;
   it does not claim the VC itself is a PoP.

5. **Depth ceilings do not round-trip.** See the table row above.

6. **Wire format.** Per §3, the fixtures are CBOR/COSE warrants from the
   reference implementation, not draft JWT AATs. No round-trip to the draft's
   normative encoding is possible with any shipping code today.

---

## 6. Behavioural findings from the reference implementation

Verified by direct experiment against `tenuo` 0.2.4. These change the adapter's
shape, so they are recorded here rather than discovered later.

1. **`Authorizer.verify_chain()` does not enforce expiry.** An expired warrant
   passes `verify_chain()` and is rejected only by `check_chain()` /
   `authorize_one()` with `ExpiredError`. A verifier built on `verify_chain()`
   alone would accept expired authority. The adapter therefore checks expiry
   explicitly **and** routes enforcement through `check_chain()`. Logged in
   `INTEROP-NOTES.md`: §7 step 3 lists TTL monotonicity as part of chain
   verification, so which layer owns leaf expiry is ambiguous.

2. **Widening is refused at derivation time, not just at verification.**
   `attenuate()` raises rather than minting a widened child. Good default; it
   means the "widening chain" fixture must be constructed deliberately.

3. **`Warrant.allows()` and `check_constraints()` are documented
   "DIAGNOSTIC USE ONLY".** The enforcement path is `Authorizer.check_chain`.
   The adapter uses only the latter for decisions.

4. **Tool-scope denial precedes PoP.** A narrowed-out tool returns
   `ToolNotAuthorized` even with no PoP signature supplied, so the block in
   Scene 4 is decisive and does not depend on PoP setup.

5. **Tampering is caught at decode.** A single flipped byte fails with
   `DeserializationError` before signature checking.

---

## 7. Proposed shape

```
integrations/aat/
  aat_chain.py       # load chain, call the reference verifier, return
                     # VerifiedChain | typed failure (bad signature, broken
                     # chain, widened scope, expired, PoP mismatch)
  aat_to_shield.py   # leaf effective authority -> Shield rules (tool scope) +
                     # a bound argument-check callable (constraints)
  credential_link.py # pass leaf jti + root identifier to the Signer via intent
  README.md
  DEMO.md
  tests/
test-vectors/aat/    # valid narrowing chain; widening chain; + generation README
```

Enforcement composition, all strictly before execution:

```
intercept(tool, args)
  → Shield.intercept(...)            # trust, DID, tool-level capability
  → Authorizer.check_chain(...)      # AAT chain + tool scope + arg constraints + PoP
  → both allow?  execute, then Signer.sign(intent with authorizedBy=jti)
  → either denies? return blocked. The tool is never called.
```

Fail-closed everywhere: any verification failure yields **no** rules and no
execution.

`vouch-mcp` wiring: `VOUCH_AAT_CHAIN` env var (the server is env-configured
today; `main()` has no argparse) plus an optional `--aat-chain` flag.
**Precedence**: when an AAT chain is present, it is applied *in addition to* the
static allow-list, never instead of it. Both must allow. That direction is the
only one that cannot widen authority relative to today's behaviour.

---

## 8. Boundaries this design holds

- No change to the credential format, cryptosuite, or Shield semantics. AAT is
  an input to the gate, not a modification of it.
- Vouch's outputs stay byte-identical. Baseline recorded below.
- No priority claims in any artefact.
- No new required credential field - the link rides in the existing `intent`.
- Apache-2.0 throughout; the dependency is Apache-2.0.

### Test baseline (recorded before any change)

```
python3 -m pytest tests/ -q --ignore=tests/test_threshold.py
→ 1447 passed, 1 skipped
```

`tests/test_threshold.py` fails at **collection** on this machine, before any of
this work: the prebuilt `core/uniffi/target/release/libvouch_core_uniffi.so` is
stale and missing the symbol `vouch_threshold_generate_key`. Pre-existing and
unrelated; noted so it is not mistaken for fallout later. Everything else runs
clean and must stay that way.

---

## 9. Scoping decisions

Both questions below were put to the maintainer and answered before any code was
written. The answers are recorded here as the decisions the implementation
follows.

**Decision 1: Python only.** Not Python + TypeScript.

**Decision 2: build against the protocol model, labelled honestly.** Fixtures
are CBOR warrant chains and are described as such; no claim is made anywhere
that this adapter consumes draft-format AAT JWTs. The optional
presentation-only RAR view described in Section 3 was not built.

The reasoning behind each, as it was put at the time:

**Scope: Python-only adapter for the demo (default), or Python + TypeScript?**

Python-only is the recommendation. It covers Shield, the Signer, `vouch-mcp` and
the whole of Scene 4, and the reference implementation's Python bindings are the
mature surface. Tenuo does publish `@tenuo/core@beta` for TypeScript, so a TS
adapter is possible, but "beta" on the dependency side would put the weakest link
in the demo path.

There is also the §3 question to confirm: proceed against the reference
implementation's protocol model, with fixtures honestly labelled as CBOR warrant
chains rather than draft JWT AATs.
