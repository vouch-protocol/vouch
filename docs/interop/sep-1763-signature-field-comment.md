# Draft comment for SEP-1763 (MCP Interceptor Framework)

**Target:** https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1763
**Venue:** Interceptors WG (`docs/community/working-groups/interceptors.mdx`)
**Status:** draft, not posted.

The SEP reserves a `signature` member on `ValidationResult` "for future use to
enable cryptographic verification of validation results at trust boundaries."
That reserved field is the attachment point for signed provenance. The comment
below raises five specification-level issues with its current shape. It is
written as a peer technical contribution, not as a proposal to adopt Vouch.

---

The `signature` field on `ValidationResult` is currently reserved with this shape:

```ts
signature?: {
  algorithm: "ed25519";
  publicKey: string;
  value: string;
}
```

with the stated intent to let recipients "verify that validations were performed
by authorized interceptor before accepting data."

I work on signed provenance for tool calls, and I think five things are worth
settling before this field gets filled in. Each is cheap to fix now and
expensive once SDKs ship.

**1. What bytes does `value` sign?**

This will bite the Go and C# reference implementations first. `ValidationResult`
carries optional members (`messages`, `suggestions`, `durationMs`, `info`), and
neither JSON object key order nor number formatting is stable across languages.
Without a normative canonicalization rule, two conformant implementations
disagree on the signing input and cross-SDK verification fails
non-deterministically — and it fails intermittently, which is the worst way for
it to fail. RFC 8785 (JCS) is the smallest fix: canonicalize the result object
with the `signature` member removed, sign those bytes. Worth stating normatively
in the SEP rather than leaving to implementers.

**2. The signature does not bind to what was validated.**

A signed `ValidationResult` attests that some authorized interceptor returned
`valid: true`. It does not attest *what* was validated. As specified, a captured
`{valid: true}` from a benign `tools/call` can be presented alongside a
different `tools/call` — same interceptor name, same signature bytes, different
payload — and it verifies. If the purpose is for a recipient to trust a
validation it did not perform, the signed content needs to cover a digest of the
intercepted payload and the event name, not just the result envelope. Suggest
adding a `payloadDigest` inside the signed content.

**3. `algorithm: "ed25519"` as a string literal has no migration path.**

Widening a literal union later is a breaking change for anyone who pattern-matched
on it. Several institutions represented in this WG have CNSA 2.0 / post-quantum
migration deadlines. Making the algorithm a registry-backed identifier now, or
carrying a self-describing key encoding, lets ML-DSA or anything else drop in
without a protocol revision.

**4. A bare `publicKey` proves control, not authorization.**

The stated goal is verifying a validation came from an *authorized* interceptor.
A raw key proves only that the signer held that key; it cannot express who
authorized that interceptor to speak on this trust boundary. That needs either a
resolvable identifier or a short chain to a pinned trust anchor. A minimal
version: permit `publicKey` to be a resolvable identifier, and let a deployment
pin one root that recognizes interceptor identities. The verifier then walks the
chain offline, with no network call on the `tools/call` path.

**5. No validity window, no revocation.**

There is no `validFrom`/`validUntil` on the signature and no status mechanism. If
an interceptor's signing key is compromised, every validation it ever signed
continues to verify indefinitely. A validity window is the minimum; a status-list
reference is the usual next step wherever signed results are retained as audit
evidence, which §7 and the audit-logging sample interceptor both imply they will
be.

---

I'm happy to turn these into a concrete PR against the SEP text — the
canonicalization rule, the `payloadDigest` binding, and a set of cross-language
test vectors so the Go and C# implementations can be checked against each other
rather than each against itself.

I have working implementations of (1), (3), (4) and (5) across four languages
with byte-identical output, which I can contribute as prior art and test vectors
rather than as a dependency.

Disclosure: I edit Vouch Protocol, a W3C Credentials CG report on signed
provenance for agent tool calls, which is why I've hit each of these. I'm not
proposing the WG adopt it — only that this field's shape shouldn't foreclose
them.
