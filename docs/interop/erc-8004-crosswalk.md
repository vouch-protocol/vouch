# Crosswalk: Vouch accountability records and ERC-8004 / ERC-8299

Status: draft. This maps Vouch's neutral accountability fields onto the Ethereum
agent-standards vocabulary so a record is portable across a Verifiable Credential
and an on-chain transport, without either side depending on the other. Vouch
defines its own fields; this document is the bridge, not a normative reference to
the ERCs.

Credit: ERC-8004 "Trustless Agents" (Identity, Reputation, Validation registries)
and ERC-8299 ("What You Read Is What You Execute", JudgmentExecutionAttestation,
the anchor-tier hierarchy) informed the field set below.

## Why a crosswalk rather than a dependency

Vouch is off-chain and crypto-agnostic (W3C Verifiable Credentials, eddsa-jcs-2022,
optional post-quantum proof set). The ERC vocabulary is on-chain and EVM-native
(ERC-721 identity, schnorr/secp256k1, on-chain settlement). Keeping the Vouch
fields self-contained lets enterprise and non-EVM deployments use the same record
shape, while this crosswalk keeps it interoperable with the on-chain world. One
record, two transports, no translation layer required at the field level.

## OutcomeCommitment

| Vouch field | ERC-8299 / 8004 | Notes |
|---|---|---|
| `commitment.digest` | `verdictHash` / `artifactHash` | salted SHA-256 over JCS-canonical claim |
| `validFrom` | `verdictTimestamp` (committed time) | self-asserted unless anchored |
| `commitment.anchor[]` `{method, reference, recomputeCmd, establishes}` | ERC-8299 Appendix B anchor hierarchy | open `method` string; `establishes` is `pre-outcome-ordering` or `existence-only`; ordering also requires the stamped time to precede settlement |
| `settlement` `{method, locator, resolutionCriteria}` | resolution descriptor | transport-neutral on the Vouch side |
| `proof` (eddsa-jcs-2022) | on-chain signature | a pointer references on-chain entries; it does not re-verify their crypto |

## OutcomeAttestation

| Vouch field | ERC-8299 / 8004 | Notes |
|---|---|---|
| `commitment.credentialId` | `commitmentRef` / `rawProposalHash` link | binds outcome to its commitment |
| `reveal` `{claim, salt}` | revealed input | lets any party recompute the committed digest |
| `outcome.matchesCommitment` | settled result | wins and losses, same record |
| `settlement` `{venue, reference}` | `settlementVenue` / `executedActionHash` | where the issuer cannot edit it |

## AccountabilityRecord (the pointer)

| Vouch field | ERC-8299 / 8004 | Notes |
|---|---|---|
| `ledger` / `recordPointer` | reputation-registry feed + entry | resolvable locator |
| `verifierKey` | published signing key | verify against this, not the presenter |
| `verifyEndpoint` | recompute service | a convenience, not a trust root |
| `reputationModel` (`recomputable` \| `asserted-score`) | registry model | recomputable carries derivation inputs |
| `publishesLosses` | feed integrity flag | a feed that hides losses is not accountability |

## Verification stance

Vouch carries the pointer and the anchor inside a signed credential, so both are
tamper-evident. Vouch does not re-verify an on-chain or schnorr-signed external
record's own cryptography; the consumer checks that record at its native venue
using `verifierKey` and the anchor `recomputeCmd`. The credential answers "who and
what record"; the linked attestation and its anchor answer "and can I check it".
