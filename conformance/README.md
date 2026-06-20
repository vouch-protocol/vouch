# Conformance issuer setup

The verified conformance badge is a signed Vouch Credential, minted by
`scripts/mint_conformance_credential.py` and chained to the project root
authority. It mirrors the verified-contributor badge exactly:

| Contributor | Conformance |
|---|---|
| `scripts/mint_contributor_credential.py` | `scripts/mint_conformance_credential.py` |
| `.github/workflows/verified-contributor.yml` | `.github/workflows/verified-conformance.yml` |
| `did:web:vouch-protocol.com:contributors` | `did:web:vouch-protocol.com:conformance` |
| `contributors/delegation.json` | `conformance/delegation.json` |
| `website/public/contributors/did.json` | `website/public/conformance/did.json` |

## One-time setup (your steps)

1. **Generate the conformance issuer keypair.**
   ```
   python -c "from vouch import keys; kp = keys.generate_identity('vouch-protocol.com:conformance'); print('PRIVATE:', kp.private_key_jwk); print('PUBLIC:', kp.public_key_jwk)"
   ```

2. **Add two GitHub repository secrets** (Settings, Secrets and variables, Actions):
   - `VOUCH_CONFORMANCE_PRIVATE_KEY` = the private key JWK (the PRIVATE line above)
   - `VOUCH_CONFORMANCE_DID` = `did:web:vouch-protocol.com:conformance`

3. **Publish the issuer public key.** Put the public JWK `x` value into
   `website/public/conformance/did.json` (replace `REPLACE_WITH_...`). On deploy
   this resolves at `https://vouch-protocol.com/conformance/did.json`, which is
   how anyone re-verifies a badge.

4. **Create the root delegation** `conformance/delegation.json`: sign a
   delegation from the project root authority to the conformance issuer DID, the
   same step you ran for `contributors/delegation.json`. With it present, every
   minted badge chains back to root.

The `verified-conformance.yml` workflow is a safe no-op until the secrets are
set, so committing the placeholders is harmless.

## Robotics

The robotics profile uses the **same issuer** and the **same mint script** with
`--profile robotics`, so no extra setup is needed. A robotics badge is issued
once the robotics conformance check lands in `vouch/conformance.py`. If you ever
want a fully separate robotics issuer DID, copy this folder to
`conformance-robotics/` and repeat the four steps with a robotics keypair.
