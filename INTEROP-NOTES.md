# Implementer notes on draft-niyikiza-oauth-attenuating-agent-tokens-01

These notes came out of building an interop adapter between Attenuating
Authorization Tokens and Vouch Protocol. The adapter verifies an AAT chain,
maps the leaf's authority onto Vouch Shield rules, enforces them before an MCP
tool call runs, and links the resulting Verifiable Credential to the AAT that
authorised the action. The code is in
[`integrations/aat/`](integrations/aat/) under Apache-2.0.

Chain verification and token derivation were not reimplemented. Both are
delegated to the reference implementation named in Appendix E.

Everything below is a note from doing the work. It is offered as implementer
feedback, not as a review of the design. Where I read something as ambiguous I
say what I did instead, so the note is actionable. The draft was clear enough to
build against on a first reading, which is not the usual experience.

Version read: `-01`, published 15 June 2026.

---

## 1. Appendix E does not give the reference implementation's location or licence

Appendix E.1 says Tenuo provides a reference implementation and describes what
it covers, but gives no repository URL, package name, or licence.

RFC 7942 Section 2 lists the implementation's name, a URL for information or
source, and the licence among the details an Implementation Status section
should carry. I found all three by searching: `github.com/tenuo-ai/tenuo`,
Apache-2.0, published to PyPI as `tenuo` and to crates.io as `tenuo`.

That search step is the kind of thing that stops an implementer who is deciding
whether the dependency is usable at all. Adding the URL and the licence to
E.1 would remove it.

## 2. The normative wire format and the reference implementation's wire format differ

The draft's normative envelope is JWT/JWS throughout: Section 3.2's claim table,
the `cnf` object, the PoP JWT in Section 5, and `par_hash` in Section 6 step 7.

The shipped reference implementation is CBOR/COSE-native. Its serialisation
produces CBOR (`to_bytes()` begins `83 01 58 a6 aa`), and version 0.2.4 exposes
no JWT encode or decode on its warrant type. Appendix E.1 is explicit that this
representation is implementation-specific and does not define a fully
interoperable CWT profile, with the profile deferred per Appendix D.

The practical consequence is that there is currently no implementation of the
draft's normative encoding to test against. An implementer who wants to consume
draft-format AAT JWTs has to write both the encoder and the chain verifier,
which is the work Appendix E would otherwise let them skip.

This shaped my adapter directly. I built against the protocol model, which is
what the reference implementation realises: the attenuation invariants of
Section 4, the derivation rule of Section 6, and the verification algorithm of
Section 7. I did not claim JWT-level interop, and the fixtures are labelled as
CBOR warrant chains rather than AATs.

Two things would help here, in rough order of value:

- An interop test vector set carrying draft-encoded JWT AATs: a root, a valid
  derived chain, and a set of chains that must fail, each with the invariant it
  violates. Even a handful would pin the encoding.
- A note in Appendix E stating plainly that the reference implementation
  realises the protocol model rather than the JWT encoding, so implementers do
  not assume otherwise.

Section 6 step 7 also qualifies the `par_hash` input with "For JWT/JWS AATs, the
parent token signing input is the JWS Signing Input." It does not define the
signing input for other serialisations. If format independence is a goal of the
model, defining "token signing input" once, per serialisation, would make the
CBOR case well specified rather than implementation-defined.

## 3. Section 7's expiry steps are not covered by the reference implementation's chain verification call

Section 7 is unambiguous that expiry is part of chain verification. Step 2e
requires `root.exp > now`, and step 4i requires `child.exp > now` under I3.

In the reference implementation these checks are not performed by
`Authorizer.verify_chain()`. They happen in `Authorizer.check_chain()` and
`Authorizer.authorize_one()`. An expired warrant passes `verify_chain()` and is
rejected only when an authorization call is made:

```python
authorizer.verify_chain([expired])          # returns normally
authorizer.check_chain([expired], tool, args)  # raises ExpiredError
```

The naming is what makes this a trap. `verify_chain` is the obvious call to
reach for when implementing Section 7, and on its own it does not implement
Section 7. An implementer who builds a verification wrapper on it, and enforces
authorization elsewhere, accepts expired authority.

My adapter checks expiry explicitly for every token in the chain and routes
enforcement through `check_chain`. There is a regression test for it
(`test_expired_leaf_rejected`) that asserts the underlying behaviour first, so
it will tell us if the reference implementation changes.

This is a note about the implementation rather than the draft. It is here
because Appendix E points implementers at that code, so the gap propagates.

## 4. Section 6 does not state a producer obligation

Section 6 specifies what a valid derived token looks like: the tool set MUST be
a subset, constraints MUST be at least as restrictive, `exp` MUST be no later,
and so on. It is written as a procedure a holder follows.

What it does not say is whether a conforming implementation MUST refuse to emit
a token that violates those rules, or whether the requirement lands purely on
the verifier. Section 7 covers the verifier side thoroughly.

The reference implementation takes the strict reading and refuses at derivation:
adding a tool, loosening a pattern, and dropping a constraint each raise rather
than minting a token. That is the safer behaviour, and I am not suggesting it
change.

It does have one practical effect worth knowing. A widening token cannot be
produced through the supported API, so the natural negative test vector, a
derived token that widens its parent, cannot be constructed by an implementer
using the reference implementation. I had to build my negative fixture a
different way: a token minted by an unrelated key claiming wider authority and
spliced in behind a genuine root. That is rejected on I5 linkage rather than on
I4 capability monotonicity, so it tests a different invariant than intended.

If the draft ships interop vectors, widening chains are the ones implementers
cannot easily make for themselves, and would be the most valuable to publish.
Stating the producer obligation explicitly, either way, would also help.

## 5. The duplicate-tool-identifier rule cannot be enforced with a stock JSON parser

Section 3.3.1 says tool identifiers MUST be unique within a `tools` map, and
that an entry containing duplicate keys is malformed and MUST be rejected.

Standard JSON parsers do not surface duplicate object keys. Python's `json`
keeps the last occurrence silently, and the common JavaScript, Go, and Rust
parsers behave the same way by default:

```python
json.loads('{"read_file": {}, "read_file": {"path": 1}}')
# {'read_file': {'path': 1}}   -- one key, no error
```

So an implementation that parses `authorization_details` with a normal JSON
library cannot detect the condition, and will silently accept a token the draft
says it must reject. Enforcing it requires a custom parse hook or a raw scan of
the token before parsing, which is worth saying out loud.

RFC 8785 does not help here either. JCS canonicalises a parsed value, so by the
time canonicalisation runs the duplicate is already gone.

A sentence in Section 3.3.1 noting that this check must happen at parse time,
before the object is materialised, would save implementers finding it the hard
way. Alternatively, if silently keeping one of the duplicates is acceptable, say
which one.

## 6. The core constraint set has no string-pattern or path type, which the motivating use case needs

Section 3.4's nine core types are `exact`, `range`, `one_of`, `not_one_of`,
`contains`, `subset`, `wildcard`, `all`, and `any`. The reasoning in the
surrounding text is clear and I think correct: these are the types with simple,
deterministic, format-independent `check` and `subsumes` rules.

The difficulty is that the draft's own motivating examples are agent tool calls
over files and URLs, and the first constraint anyone reaches for is a path or
prefix pattern. Restricting `read_file` to `reports/*` cannot be expressed with
the core nine. `one_of` requires enumerating every path in advance, which is not
workable for a filesystem.

Section 3.5.3 gives Path Containment as the worked example of an extension
registration, which suggests this is anticipated. But no such type is registered
yet, and Section 10.3.3's initial registry entries are the core types. So the
first thing a real deployment does takes it outside the interoperable set, and
two independent implementations of the draft cannot exchange the constraint that
the draft's own examples motivate.

The reference implementation ships `Pattern`, `Regex`, `Path`, `Subpath`,
`Cidr`, `Url`, `UrlPattern`, `UrlSafe`, `Cmd`, `Shlex`, `CEL`, `Not`, and
`AnyOf` beyond the core nine, which suggests the same pressure showed up in
practice. My demo uses `Pattern("reports/*")`, and I flag in my own
documentation that it is not a core AAT constraint type.

Registering one path-containment type in the initial registry, with its
`subsumes` procedure defined, would let a common case be interoperable at
publication rather than after it.

On a related point, Section 3.4's fail-closed rule for unrecognised
`constraint_type` values is good and I implemented it. It does mean that
adopting any extension type partitions deployments until the extension is widely
implemented, which strengthens the argument for having the common one in the
base registry.

## 7. The PoP JWT carries argument values in the clear

Section 5.2 defines `hta` as an object holding the tool arguments for the
invocation, with argument names as keys and argument values as values. Not a
digest of them.

A JWS compact serialisation is signed, not encrypted, and the payload is
base64url. So every PoP JWT exposes the full argument values of the call it
authorises, to anything that handles it: proxies, gateways, request logs, error
reporting. For the draft's own examples this can mean file paths, query strings,
recipient addresses, and amounts.

Two consequences worth a sentence in Section 9:

- Privacy. Argument values are frequently the sensitive part of an agent tool
  call, more so than the tool name.
- Size. Arguments can be large. A tool taking a document body puts that body in
  every PoP JWT, and header-carried tokens meet size limits in practice.

A digest form would address both. `hta` could carry
`base64url(SHA-256(JCS(args)))` instead of the arguments, since the enforcement
point already has the arguments from the invocation itself and only needs to
confirm they match. The current design does not appear to need the values
themselves to be present. If there is a reason it does, saying so would help,
because the digest form is what an implementer will reach for.

The naming is also worth a look. `hta` sits close to DPoP's `htm` and `htu`
(RFC 9449), which are short strings describing an HTTP request. `hta` is an
object with different semantics. Something like `args` or `aat_args` would
signal the difference, and would match the `aat_`-prefixed claims alongside it.

## 8. Audience binding is optional by default

`aat_aud` is OPTIONAL in Table 4. Deployments that require audience binding MUST
require the claim and enforce it, which puts the choice with the deployment.

The default posture is then that a PoP JWT is valid at any enforcement point
that trusts the chain, within the clock tolerance of Section 5.3. Where one leaf
token is presented to several enforcement points, a PoP captured by one can be
replayed to another for the same tool and arguments. Section 8.5 covers replay
and notes that detecting `jti` reuse depends on stateful tracking being
deployed, which is a separate control and is also optional.

Making `aat_aud` REQUIRED, or stating a default in Section 5.3 for what an
enforcement point should do when it is absent, would make the safer
configuration the one implementers get without thinking about it.

---

## Things that were straightforward to implement

Worth recording, since feedback documents tend to list only friction.

- The five invariants I1 to I5 map cleanly to code and are easy to test
  individually. Naming them and referring to them by number throughout is a real
  help when writing tests, because a failure can be attributed to a specific
  invariant.
- Offline derivation works exactly as described. No network access is needed and
  none is attempted.
- The narrow-only rule needed no adaptation to sit alongside Vouch's own
  delegation model, which enforces the same non-expansion invariant over a
  different dimension set. That the two composed without either side changing
  its semantics is the main result of this exercise.
- Exact-string tool matching with no normalization is the right call and made
  the mapping to our Shield rules trivial. The explicit "MUST NOT apply Unicode
  normalization, URI normalization, case folding, percent decoding, or alias
  resolution" is the kind of sentence that prevents divergent implementations.
- The fail-closed rule for unknown constraint types, paired with the requirement
  to ignore unrecognised top-level claims, draws the line in the right place.

## What was mapped, and what was lossy

Recorded in [`integrations/aat/DESIGN.md`](integrations/aat/DESIGN.md). The
short version, from the AAT side:

- Tool names, the narrow-only invariant, `jti`, and `exp` map cleanly onto Vouch
  concepts.
- AAT's per-argument constraints have no equivalent in Vouch Shield's rule
  model, which is per-DID capability levels and never sees call arguments. I did
  not flatten them, because doing so would widen authority. Argument evaluation
  stays with the reference implementation and runs in the same pre-execution
  step.
- Going the other way, Vouch's `rate` and `policy` delegation dimensions have no
  equivalent in AAT's core constraint set and would need registered extension
  types.
- `del_max_depth` has no counterpart in Vouch, which sets no fixed depth limit.
  AAT to Vouch is safe; the reverse would mean inventing a ceiling.
- A derived token's `iss` is a JWK Thumbprint URI while Vouch uses DIDs. Neither
  specification defines a conversion. `did:key` is the closest analogue.

Happy to supply the adapter, its tests, or the fixtures if any of this is useful
in preparing `-02`.
