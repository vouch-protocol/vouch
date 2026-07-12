# Vouch Verified Contributor credential

Vouch Protocol issues a signed credential to people who contribute to it.
When you land a merged pull request on the repository, an automated
workflow mints a Vouch Verified Contributor credential for the author of
that pull request's commits. This is the project using its own protocol:
the badge is a real Verifiable Credential, not a decorative image.

## What you get

- A certificate page at `https://vouch-protocol.com/c/<login>/<pr>`.
- A listing on the contributors page at `https://vouch-protocol.com/contributors`.
- A comment on your pull request with the badge, a copy-paste snippet,
  and the full credential inline.

The badge is offered, never required. Add it to your profile or site if
you want to.

## What the credential is

- A Verifiable Credential signed with the `eddsa-jcs-2022` cryptosuite
  (Ed25519 over JCS-canonicalized bytes), the same default format every
  Vouch SDK produces.
- Issued by `did:web:vouch-protocol.com:contributors`.
- Chained back to the project root authority `did:web:vouch-protocol.com`
  through a delegation, so a verifier can walk from the badge to the root
  identity.
- The subject is the contributor (the author of the merged commits), so
  credit stays correct even when a maintainer relays a contribution for
  someone else.

## Verifying the badge

Because it is a normal Vouch credential, anyone can verify it with the
SDK or the hosted verifier. The issuer public key is published in the DID
document at `https://vouch-protocol.com/contributors/did.json`. In Python:

```python
from vouch import Verifier

# `credential` is the JSON from the pull request comment or the
# certificate page; `issuer_public_jwk` is the publicKeyJwk from the
# contributor DID document.
is_valid, passport = Verifier.verify_credential(credential, public_key=issuer_public_jwk)
print(is_valid, passport.subject_did)
```

The certificate page verifies the same credential against the published
contributor DID document before it is rendered.

## How it works end to end

1. Your pull request merges.
2. A workflow resolves the contributor from the commit authors, skipping
   the maintainer and bots.
3. It mints the credential and self-verifies it against the published DID.
4. It publishes the certificate page and adds you to the contributors
   list, then waits for the site to deploy.
5. It posts the congratulatory comment on your pull request.

## Links

- Contributors: https://vouch-protocol.com/contributors
- Repository: https://github.com/vouch-protocol/vouch
- Good first issues: https://github.com/vouch-protocol/vouch/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22
