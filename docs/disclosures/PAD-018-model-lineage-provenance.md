# PAD-018: Method for Cryptographic Model Lineage Provenance via Birth Certificate Protocol

**Identifier:** PAD-018
**Title:** Method for Cryptographic Model Lineage Provenance via Birth Certificate Protocol ("Birth Certificate Protocol")
**Publication Date:** February 14, 2026
**Prior Art Effective Date:** February 14, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** AI Safety / Model Provenance / Supply Chain Integrity / Recursive Self-Improvement Governance
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for establishing cryptographic chain of custody for AI models themselves---not merely their outputs---through a comprehensive "Birth Certificate" that binds a model's identity to its verifiable lineage. As AI systems increasingly participate in their own creation (OpenAI disclosed that GPT-5.3 Codex was "instrumental in creating itself"), the provenance of intelligence itself becomes a critical safety and governance requirement. Without cryptographic model lineage, the AI ecosystem faces an existential trust gap: we cannot verify what data trained a model, which prior models contributed to its creation, whether it was structurally modified after signing, or how many generations of recursive self-improvement it has undergone.

The protocol introduces several interlocking mechanisms:

1. **Training Data Provenance**: A Merkle root of the training dataset cryptographically binding what data went into the model, enabling verifiable inclusion and exclusion proofs without exposing proprietary datasets.
2. **Parent Model Lineage Graph**: A signed directed acyclic graph (DAG) recording which prior models contributed to the current model's creation---a verifiable family tree for AI.
3. **Self-Modification Audit Trail**: When a model contributes to its own training or architecture, a cryptographic log of specific contributions, safety review attestations, and human oversight checkpoints.
4. **Architecture Provenance**: Cryptographic binding of model architecture (layer definitions, attention patterns, activation functions) to the birth certificate, detecting unauthorized structural modifications.
5. **Generation Counter**: A monotonically increasing, cryptographically enforced counter tracking recursive self-improvement generations, making it impossible to conceal the depth of a model's self-improvement lineage.
6. **C2PA Model Credentials Extension**: Extension of the C2PA Content Credentials standard from "who made this media" to "who made this intelligence," introducing model birth certificates as a new C2PA assertion type.
7. **Behavioral Fingerprinting**: Statistical signatures derived from model behavior that can detect post-signing tampering, weight manipulation, or unauthorized fine-tuning---even when the model binary is inaccessible.
8. **Lineage Verification at Inference Time**: A protocol enabling verifiers to inspect a model's birth certificate before accepting its outputs, creating a trust gateway between model provenance and output validity.

Unlike model cards (unstructured documentation), model registries (unsigned metadata), or software supply chain tools (designed for deterministic artifacts), this protocol addresses the unique challenges of AI model provenance: non-deterministic training processes, recursive self-improvement loops, behavioral identity beyond binary identity, and the emerging reality that AI is building itself.

---

## 2. Problem Statement

### 2.1 AI Is Now Building Itself

The era of purely human-authored AI has ended. Contemporary frontier models are increasingly involved in their own creation:

- **GPT-5.3 Codex**: OpenAI disclosed that its coding model was "instrumental in creating itself," contributing to its own training pipeline, evaluation harness, and architecture search.
- **Recursive self-improvement**: Models are used to generate synthetic training data, evaluate other models, optimize hyperparameters, propose architectural changes, and write the code that trains successor models.
- **Distillation chains**: Knowledge distilled from Model A into Model B, then from Model B into Model C, creates lineage chains that are currently untracked and unverifiable.

Without cryptographic provenance, we cannot answer fundamental questions:

| Question | Current State | Required State |
|---|---|---|
| What data trained this model? | Trust the lab's claim | Verify against Merkle proof |
| Which models contributed to this model? | Unknown / untracked | Signed lineage DAG |
| Did this model help train itself? | No audit trail | Self-modification log with safety attestations |
| Has this model been modified since release? | Binary hash (fragile) | Behavioral fingerprint + architecture proof |
| How many self-improvement generations deep is this? | Unknown | Cryptographic generation counter |
| Is this model authorized for this deployment? | No binding mechanism | C2PA-style model credential |

### 2.2 The Provenance Gap: Models vs. Outputs

Existing provenance systems (including earlier Vouch Protocol PADs) focus on the **outputs** of AI systems:

```
Current Vouch Protocol Coverage:
    [Agent Identity] --> [Agent Action] --> [Output Signature]
         PAD-001           PAD-002            PAD-017

Missing Coverage:
    [Training Data] --> [Training Process] --> [Model Identity] --> ???
         ???                  ???                   ???
```

This gap means a perfectly signed output from a perfectly identified agent tells us nothing about the model powering that agent. A Vouch-signed response could originate from:
- A model trained on stolen data
- A model that has been covertly fine-tuned to inject backdoors
- A model claiming to be GPT-5 but actually a modified derivative
- A model that is the 47th generation of unsupervised recursive self-improvement

### 2.3 The Recursive Self-Improvement Threat

Recursive self-improvement creates unique provenance challenges:

```
Generation 0 (Human-authored):
    Researchers design architecture, curate data, train model
    → Provenance: CLEAR (human decisions documented)

Generation 1 (AI-assisted):
    Model G0 helps generate training data, suggests architecture changes
    → Provenance: PARTIALLY CLEAR (which suggestions came from G0?)

Generation 2 (AI-driven):
    Model G1 designs training curriculum, proposes novel layers,
    writes training code, evaluates results, selects next architecture
    → Provenance: OPAQUE (human oversight diminishing)

Generation N (Autonomous):
    Model G(N-1) creates G(N) with minimal human involvement
    → Provenance: UNKNOWN (what is this model? who is responsible?)
```

Each generation compounds the provenance gap. Without a cryptographic audit trail, by Generation 3-4 the lineage is effectively untraceable.

### 2.4 Model Identity Is Not Binary Identity

Traditional software supply chain security (SLSA, Sigstore, SBOM) treats artifacts as deterministic binaries. AI models break this assumption:

1. **Same weights, different behavior**: Quantization, batching, and hardware differences cause identical weights to produce different outputs.
2. **Different weights, same behavior**: Knowledge distillation can produce a functionally equivalent model with entirely different parameters.
3. **Partial modification**: Fine-tuning changes a small fraction of weights but can fundamentally alter model behavior (e.g., inserting a backdoor via 0.01% weight modification).
4. **Non-deterministic training**: The same data + architecture + hyperparameters can produce different models due to random initialization and training order.

Binary hashing (SHA-256 of model file) is therefore **necessary but insufficient** for model identity. A model's identity must also encompass its behavioral characteristics and its lineage.

### 2.5 The Accountability Vacuum

When a model causes harm, the current accountability chain breaks at the model layer:

```
Harm Event
    └── Which agent did this?     → PAD-001 (Agent Identity) ✓
    └── Who authorized it?        → PAD-002 (Delegation Chain) ✓
    └── What was the reasoning?   → PAD-017 (Proof of Reasoning) ✓
    └── Which MODEL did this?     → ??? ✗
    └── What data trained it?     → ??? ✗
    └── Who trained it?           → ??? ✗
    └── Was it modified?          → ??? ✗
    └── How many generations?     → ??? ✗
```

PAD-018 closes these gaps.

---

## 3. Solution: The Birth Certificate Protocol

### 3.1 Model Birth Certificate Structure

Every AI model receives a cryptographically signed "Birth Certificate" at the completion of training. This certificate is the atomic unit of model provenance.

#### 3.1.1 Birth Certificate Schema

```json
{
  "$schema": "https://vouch-protocol.org/schemas/pad-018/birth-certificate/v1",
  "certificate_id": "vouch:model:bc-2026-02-14-a8f3d1e7...",
  "version": "1.0",
  "model_identity": {
    "name": "frontier-model-v3.1",
    "did": "did:key:z6MkModel...",
    "organization": "did:web:lab.example.com",
    "purpose": "General-purpose language model",
    "creation_timestamp": "2026-02-14T00:00:00Z",
    "binary_hash": "sha256:H(model_weights_file)",
    "architecture_hash": "sha256:H(canonical_architecture_definition)",
    "parameter_count": 175000000000,
    "behavioral_fingerprint": {
      "method": "vouch:fingerprint:stochastic-probe-v1",
      "fingerprint_hash": "sha256:H(behavioral_fingerprint_vector)",
      "probe_set_hash": "sha256:H(standardized_probe_inputs)",
      "timestamp": "2026-02-14T00:00:00Z"
    }
  },
  "training_data_provenance": {
    "dataset_merkle_root": "sha256:merkle_root_of_training_data",
    "dataset_size": 15000000000000,
    "dataset_description": "Web crawl 2024-2026 + curated sources",
    "inclusion_proof_endpoint": "https://lab.example.com/proofs/inclusion",
    "exclusion_proof_endpoint": "https://lab.example.com/proofs/exclusion",
    "data_governance_attestation": {
      "consent_audit": "sha256:H(consent_audit_report)",
      "copyright_review": "sha256:H(copyright_review_report)",
      "bias_audit": "sha256:H(bias_audit_report)",
      "attested_by": "did:key:z6MkAuditor..."
    }
  },
  "parent_lineage": {
    "lineage_type": "fine_tune",
    "parents": [
      {
        "certificate_id": "vouch:model:bc-2025-09-01-b2c4e6f8...",
        "relationship": "base_model",
        "contribution": "Pre-trained weights used as initialization",
        "parent_generation": 1,
        "parent_certificate_hash": "sha256:H(parent_birth_certificate)"
      },
      {
        "certificate_id": "vouch:model:bc-2025-11-15-d4e6f8a0...",
        "relationship": "distillation_teacher",
        "contribution": "Provided soft labels for distillation",
        "parent_generation": 2,
        "parent_certificate_hash": "sha256:H(teacher_birth_certificate)"
      }
    ],
    "lineage_dag_root": "sha256:merkle_root_of_lineage_DAG"
  },
  "self_modification_log": {
    "self_referential": true,
    "generation_counter": 3,
    "contributions": [
      {
        "contribution_id": "contrib-001",
        "type": "synthetic_training_data",
        "description": "Model G2 generated 500M synthetic reasoning examples",
        "data_hash": "sha256:H(synthetic_data_batch)",
        "safety_review": {
          "reviewer_type": "human",
          "reviewer_did": "did:key:z6MkReviewer...",
          "review_timestamp": "2026-01-20T14:30:00Z",
          "review_hash": "sha256:H(safety_review_report)",
          "verdict": "APPROVED_WITH_CONDITIONS",
          "conditions": ["filtered_for_harmful_content", "diversity_balanced"]
        }
      },
      {
        "contribution_id": "contrib-002",
        "type": "architecture_suggestion",
        "description": "Model G2 proposed sparse attention pattern modification",
        "diff_hash": "sha256:H(architecture_diff)",
        "safety_review": {
          "reviewer_type": "committee",
          "reviewer_dids": [
            "did:key:z6MkReviewer1...",
            "did:key:z6MkReviewer2...",
            "did:key:z6MkReviewer3..."
          ],
          "review_timestamp": "2026-01-22T09:00:00Z",
          "review_hash": "sha256:H(committee_review_report)",
          "verdict": "APPROVED",
          "conditions": []
        }
      }
    ]
  },
  "architecture_provenance": {
    "architecture_definition_hash": "sha256:H(architecture.yaml)",
    "layer_manifest": [
      {
        "layer_id": "transformer_block_0",
        "type": "transformer_attention",
        "config_hash": "sha256:H(layer_0_config)",
        "parameter_count": 2500000
      }
    ],
    "layer_manifest_merkle_root": "sha256:merkle_root_of_layers",
    "training_code_hash": "sha256:H(training_pipeline_code)",
    "training_config_hash": "sha256:H(hyperparameters_and_config)"
  },
  "generation_counter": {
    "value": 3,
    "previous_generation_certificate": "vouch:model:bc-2025-11-15-d4e6f8a0...",
    "counter_chain_hash": "sha256:H(gen0_hash || gen1_hash || gen2_hash || gen3_value)",
    "human_oversight_attestation": {
      "attested_by": "did:key:z6MkOverseer...",
      "attestation": "Human oversight maintained at generation 3",
      "oversight_level": "COMMITTEE_REVIEW",
      "timestamp": "2026-02-14T00:00:00Z"
    }
  },
  "c2pa_extension": {
    "manifest_uri": "self#vouch/model-birth-certificate",
    "assertion_type": "vouch.model.birthCertificate",
    "c2pa_version": "2.1",
    "claim_generator": "Vouch Protocol Birth Certificate Generator/1.0"
  },
  "signature": {
    "algorithm": "Ed25519",
    "signer_did": "did:key:z6MkLab...",
    "signature": "ed25519_signature_over_canonical_certificate",
    "timestamp": "2026-02-14T00:00:00Z",
    "co_signers": [
      {
        "role": "safety_board",
        "did": "did:key:z6MkSafetyBoard...",
        "signature": "ed25519_co_signature"
      }
    ]
  }
}
```

#### 3.1.2 Certificate Signing Process

```python
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
import hashlib
import json
import time


def issue_birth_certificate(
    model_identity: dict,
    training_data_provenance: dict,
    parent_lineage: dict,
    self_modification_log: dict,
    architecture_provenance: dict,
    generation_counter: dict,
    signer_private_key: Ed25519PrivateKey,
    signer_did: str,
    co_signers: list = None,
) -> dict:
    """
    Issue a cryptographically signed Birth Certificate for an AI model.

    This is the core ceremony that binds a model's identity to its
    verifiable lineage. MUST be performed at training completion,
    BEFORE the model is deployed or distributed.
    """
    certificate = {
        "version": "1.0",
        "certificate_id": generate_certificate_id(),
        "model_identity": model_identity,
        "training_data_provenance": training_data_provenance,
        "parent_lineage": parent_lineage,
        "self_modification_log": self_modification_log,
        "architecture_provenance": architecture_provenance,
        "generation_counter": generation_counter,
        "c2pa_extension": {
            "manifest_uri": "self#vouch/model-birth-certificate",
            "assertion_type": "vouch.model.birthCertificate",
            "c2pa_version": "2.1",
            "claim_generator": "Vouch Protocol Birth Certificate Generator/1.0",
        },
    }

    # Canonical serialization for deterministic signing
    canonical = canonicalize(certificate)
    canonical_bytes = canonical.encode("utf-8")

    # Ed25519 signature over canonical certificate
    signature = signer_private_key.sign(canonical_bytes)

    certificate["signature"] = {
        "algorithm": "Ed25519",
        "signer_did": signer_did,
        "signature": signature.hex(),
        "timestamp": iso_timestamp(),
        "co_signers": [],
    }

    # Collect co-signatures (e.g., safety board)
    if co_signers:
        for co_signer in co_signers:
            co_sig = co_signer["private_key"].sign(canonical_bytes)
            certificate["signature"]["co_signers"].append({
                "role": co_signer["role"],
                "did": co_signer["did"],
                "signature": co_sig.hex(),
            })

    return certificate


def canonicalize(obj: dict) -> str:
    """
    Deterministic JSON serialization for consistent hashing.
    Keys sorted, no whitespace, UTF-8 encoding.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

### 3.2 Training Data Provenance

The training data provenance component creates a cryptographic commitment to the training dataset without requiring disclosure of the data itself.

#### 3.2.1 Training Data Merkle Tree

```
                        Dataset Merkle Root
                       /                    \
                  H(L+R)                    H(L+R)
                 /      \                  /      \
            H(L+R)      H(L+R)       H(L+R)      H(L+R)
           /    \       /    \       /    \       /    \
        [Shard  [Shard  [Shard  [Shard  [Shard  [Shard  [Shard  [Shard
          0]      1]      2]      3]      4]      5]      6]      7]
          |       |       |       |       |       |       |       |
        H(data) H(data) H(data) H(data) H(data) H(data) H(data) H(data)
```

Each leaf represents a shard of the training data. The shard hash is computed over the canonical content of that shard, enabling two critical operations:

#### 3.2.2 Inclusion Proof

Proves that a specific data item WAS in the training set:

```python
def generate_inclusion_proof(
    data_item: bytes,
    shard_index: int,
    merkle_tree: MerkleTree,
) -> InclusionProof:
    """
    Generate a Merkle inclusion proof demonstrating that a specific
    data item was part of the training dataset.

    Use case: A data owner wants to verify their content was used
    in training (for licensing compliance or opt-out enforcement).
    """
    item_hash = hashlib.sha256(data_item).hexdigest()

    # Verify item exists in the specified shard
    shard = merkle_tree.get_shard(shard_index)
    if item_hash not in shard.item_hashes:
        raise ValueError("Data item not found in specified shard")

    # Generate Merkle proof path from leaf to root
    proof_path = merkle_tree.generate_proof(shard_index)

    return InclusionProof(
        item_hash=item_hash,
        shard_index=shard_index,
        shard_hash=shard.hash,
        proof_path=proof_path,
        merkle_root=merkle_tree.root,
        certificate_id=merkle_tree.certificate_id,
    )


def verify_inclusion_proof(proof: InclusionProof, birth_certificate: dict) -> bool:
    """
    Verify that a claimed inclusion proof is valid against the
    birth certificate's dataset Merkle root.
    """
    # Reconstruct root from proof path
    computed_root = proof.shard_hash
    for sibling_hash, direction in proof.proof_path:
        if direction == "left":
            computed_root = hashlib.sha256(
                (sibling_hash + computed_root).encode()
            ).hexdigest()
        else:
            computed_root = hashlib.sha256(
                (computed_root + sibling_hash).encode()
            ).hexdigest()

    # Compare against birth certificate
    expected_root = birth_certificate["training_data_provenance"]["dataset_merkle_root"]
    return computed_root == expected_root
```

#### 3.2.3 Exclusion Proof

Proves that a specific data item was NOT in the training set:

```python
def generate_exclusion_proof(
    data_item: bytes,
    sorted_merkle_tree: SortedMerkleTree,
) -> ExclusionProof:
    """
    Generate a Merkle exclusion proof demonstrating that a specific
    data item was NOT part of the training dataset.

    Uses a sorted Merkle tree where leaves are ordered by hash value.
    An exclusion proof shows the two adjacent leaves that would
    bracket the item's hash if it existed---proving no leaf with
    that hash is present.

    Use case: A lab wants to prove it did NOT train on a specific
    copyrighted work, in response to a legal challenge.
    """
    item_hash = hashlib.sha256(data_item).hexdigest()

    # Find the two adjacent leaves that bracket the item hash
    left_neighbor, right_neighbor = sorted_merkle_tree.find_neighbors(item_hash)

    # Verify the item hash falls between these neighbors
    assert left_neighbor.hash < item_hash < right_neighbor.hash, \
        "Item hash not properly bracketed---item may exist in tree"

    # Generate proofs for both neighbors
    left_proof = sorted_merkle_tree.generate_proof(left_neighbor.index)
    right_proof = sorted_merkle_tree.generate_proof(right_neighbor.index)

    return ExclusionProof(
        item_hash=item_hash,
        left_neighbor_hash=left_neighbor.hash,
        right_neighbor_hash=right_neighbor.hash,
        left_proof=left_proof,
        right_proof=right_proof,
        adjacency_proof=sorted_merkle_tree.prove_adjacency(
            left_neighbor.index, right_neighbor.index
        ),
        merkle_root=sorted_merkle_tree.root,
    )
```

#### 3.2.4 Data Governance Attestation

The training data provenance includes third-party attestations for governance compliance:

```json
{
  "data_governance_attestation": {
    "consent_audit": {
      "auditor_did": "did:key:z6MkAuditor...",
      "standard": "GDPR Article 6 / AI Act Article 10",
      "scope": "Verified consent or legitimate basis for all PII-containing shards",
      "report_hash": "sha256:H(consent_audit_report)",
      "signature": "ed25519:auditor_signs_report_hash"
    },
    "copyright_review": {
      "reviewer_did": "did:key:z6MkCopyrightReviewer...",
      "standard": "EU AI Act / US Copyright Office guidance",
      "scope": "Reviewed training data for copyrighted material inclusion",
      "report_hash": "sha256:H(copyright_review_report)",
      "signature": "ed25519:reviewer_signs_report_hash"
    },
    "bias_audit": {
      "auditor_did": "did:key:z6MkBiasAuditor...",
      "standard": "NIST AI RMF / ISO 42001",
      "scope": "Assessed demographic representation and potential bias sources",
      "report_hash": "sha256:H(bias_audit_report)",
      "signature": "ed25519:auditor_signs_report_hash"
    }
  }
}
```

### 3.3 Parent Model Lineage Graph

AI models are not created in isolation. They inherit from, distill from, merge with, and build upon prior models. The lineage graph captures these relationships as a cryptographically signed DAG.

#### 3.3.1 Lineage DAG Structure

```
                    ┌──────────────────┐
                    │   Foundation     │
                    │   Model v1.0     │
                    │   (Gen 0)        │
                    │   BC: bc-001...  │
                    └────────┬─────────┘
                             │
                    ┌────────┴─────────┐
                    │                  │
           ┌────────▼──────┐  ┌───────▼───────┐
           │  Fine-tuned   │  │  Distilled    │
           │  Model v2.0   │  │  Model v2.1   │
           │  (Gen 0)      │  │  (Gen 0)      │
           │  BC: bc-002.. │  │  BC: bc-003.. │
           └────────┬──────┘  └───────┬───────┘
                    │                 │
                    └────────┬────────┘
                             │ (merged)
                    ┌────────▼─────────┐
                    │  Merged Model    │
                    │  v3.0            │
                    │  (Gen 0)         │
                    │  BC: bc-004...   │
                    └────────┬─────────┘
                             │
                             │ (model contributes to own training)
                             │
                    ┌────────▼─────────┐
                    │  Self-improved   │
                    │  Model v3.1      │
                    │  (Gen 1) ←───── GENERATION INCREMENTED
                    │  BC: bc-005...   │
                    └──────────────────┘
```

#### 3.3.2 Lineage Relationship Types

```json
{
  "lineage_relationship_types": {
    "base_model": {
      "description": "Pre-trained weights used as initialization",
      "inherits_generation": true,
      "generation_increment": 0
    },
    "fine_tune_source": {
      "description": "Model fine-tuned on new data without self-referential contribution",
      "inherits_generation": true,
      "generation_increment": 0
    },
    "distillation_teacher": {
      "description": "Teacher model providing soft labels for knowledge distillation",
      "inherits_generation": true,
      "generation_increment": 0
    },
    "merge_contributor": {
      "description": "Model whose weights were merged via model merging techniques",
      "inherits_generation": true,
      "generation_increment": 0
    },
    "self_referential_contributor": {
      "description": "The model (or its predecessor) contributed to its own training",
      "inherits_generation": true,
      "generation_increment": 1
    },
    "synthetic_data_generator": {
      "description": "Model that generated synthetic training data",
      "inherits_generation": true,
      "generation_increment": 0,
      "note": "Becomes self_referential if generator is same lineage as trainee"
    },
    "architecture_contributor": {
      "description": "Model that proposed architectural changes used in this model",
      "inherits_generation": true,
      "generation_increment": 1
    },
    "evaluation_judge": {
      "description": "Model that served as judge/evaluator during RLHF or training",
      "inherits_generation": false,
      "generation_increment": 0,
      "note": "Judge does not contribute to weights, only to selection"
    }
  }
}
```

#### 3.3.3 Lineage Verification

```python
def verify_lineage_chain(birth_certificate: dict, certificate_registry) -> LineageReport:
    """
    Recursively verify the entire lineage chain of a model,
    from the current certificate back to the root ancestor(s).

    Checks:
    1. Every claimed parent actually exists and has a valid certificate
    2. Parent certificate hashes match claimed hashes
    3. Generation counters are consistent with lineage relationships
    4. No cycles exist in the lineage DAG
    5. Self-referential contributions have required safety attestations
    """
    visited = set()
    lineage_issues = []

    def _verify_recursive(cert_id: str, expected_gen: int, depth: int):
        if cert_id in visited:
            # DAG allows shared ancestors---only flag actual cycles
            return
        visited.add(cert_id)

        cert = certificate_registry.get(cert_id)
        if cert is None:
            lineage_issues.append(
                LineageIssue(
                    severity="CRITICAL",
                    message=f"Parent certificate {cert_id} not found in registry",
                    depth=depth,
                )
            )
            return

        # Verify certificate signature
        if not verify_certificate_signature(cert):
            lineage_issues.append(
                LineageIssue(
                    severity="CRITICAL",
                    message=f"Certificate {cert_id} has invalid signature",
                    depth=depth,
                )
            )
            return

        # Verify generation counter consistency
        actual_gen = cert["generation_counter"]["value"]
        parents = cert.get("parent_lineage", {}).get("parents", [])

        for parent in parents:
            parent_cert = certificate_registry.get(parent["certificate_id"])
            if parent_cert is None:
                lineage_issues.append(
                    LineageIssue(
                        severity="CRITICAL",
                        message=f"Parent {parent['certificate_id']} missing",
                        depth=depth + 1,
                    )
                )
                continue

            # Verify parent certificate hash matches
            parent_hash = hashlib.sha256(
                canonicalize(parent_cert).encode()
            ).hexdigest()
            if parent_hash != parent["parent_certificate_hash"]:
                lineage_issues.append(
                    LineageIssue(
                        severity="CRITICAL",
                        message=f"Parent certificate hash mismatch for "
                                f"{parent['certificate_id']}",
                        depth=depth + 1,
                    )
                )

            # Verify self-modification has safety review
            if parent["relationship"] == "self_referential_contributor":
                _verify_self_modification_safety(cert, parent, lineage_issues, depth)

            # Recurse
            _verify_recursive(
                parent["certificate_id"],
                parent.get("parent_generation", 0),
                depth + 1,
            )

    _verify_recursive(
        birth_certificate["certificate_id"],
        birth_certificate["generation_counter"]["value"],
        depth=0,
    )

    return LineageReport(
        certificate_id=birth_certificate["certificate_id"],
        total_ancestors=len(visited),
        max_depth=max((issue.depth for issue in lineage_issues), default=0),
        generation=birth_certificate["generation_counter"]["value"],
        issues=lineage_issues,
        verdict="VALID" if not any(
            i.severity == "CRITICAL" for i in lineage_issues
        ) else "INVALID",
    )


def _verify_self_modification_safety(cert, parent_ref, issues, depth):
    """
    When a model is self-referential (contributed to its own training),
    verify that mandatory safety reviews were conducted.
    """
    mod_log = cert.get("self_modification_log", {})
    contributions = mod_log.get("contributions", [])

    if not contributions:
        issues.append(
            LineageIssue(
                severity="CRITICAL",
                message="Self-referential lineage claimed but no contributions logged",
                depth=depth,
            )
        )
        return

    for contrib in contributions:
        review = contrib.get("safety_review")
        if review is None:
            issues.append(
                LineageIssue(
                    severity="CRITICAL",
                    message=f"Contribution {contrib['contribution_id']} "
                            f"lacks safety review",
                    depth=depth,
                )
            )
        elif review.get("verdict") not in ("APPROVED", "APPROVED_WITH_CONDITIONS"):
            issues.append(
                LineageIssue(
                    severity="HIGH",
                    message=f"Contribution {contrib['contribution_id']} "
                            f"safety review verdict: {review.get('verdict')}",
                    depth=depth,
                )
            )
```

### 3.4 Self-Modification Audit Trail

When a model contributes to its own training (recursive self-improvement), additional safeguards are mandatory.

#### 3.4.1 Self-Modification Types

| Type | Description | Risk Level | Required Oversight |
|---|---|---|---|
| `synthetic_training_data` | Model generates data used in its own next-gen training | MEDIUM | Automated review + human spot-check |
| `architecture_suggestion` | Model proposes changes to its own architecture | HIGH | Human committee review |
| `hyperparameter_optimization` | Model tunes its own training hyperparameters | MEDIUM | Automated bounds checking + logging |
| `training_code_modification` | Model writes or modifies its own training code | CRITICAL | Human committee review + code audit |
| `evaluation_criteria` | Model defines or modifies criteria used to evaluate itself | CRITICAL | Independent human-defined criteria required |
| `reward_signal_modification` | Model influences its own reward/loss function | CRITICAL | Mandatory human override; must be flagged |

#### 3.4.2 Safety Review Requirements by Risk Level

```python
SAFETY_REVIEW_REQUIREMENTS = {
    "MEDIUM": {
        "min_reviewers": 1,
        "reviewer_types": ["human", "automated"],
        "automated_checks": [
            "content_safety_scan",
            "distribution_shift_analysis",
            "bias_regression_test",
        ],
        "human_spot_check_rate": 0.05,  # 5% manual review
        "max_review_age_hours": 168,    # 7 days
    },
    "HIGH": {
        "min_reviewers": 3,
        "reviewer_types": ["human"],
        "automated_checks": [
            "content_safety_scan",
            "distribution_shift_analysis",
            "bias_regression_test",
            "capability_boundary_test",
            "alignment_regression_suite",
        ],
        "human_spot_check_rate": 0.20,  # 20% manual review
        "max_review_age_hours": 72,     # 3 days
    },
    "CRITICAL": {
        "min_reviewers": 5,
        "reviewer_types": ["human"],
        "automated_checks": [
            "content_safety_scan",
            "distribution_shift_analysis",
            "bias_regression_test",
            "capability_boundary_test",
            "alignment_regression_suite",
            "deception_probe_battery",
            "power_seeking_evaluation",
            "self_preservation_test",
        ],
        "human_spot_check_rate": 1.0,   # 100% manual review
        "max_review_age_hours": 24,     # 1 day
        "requires_board_approval": True,
    },
}
```

#### 3.4.3 Audit Trail Immutability

The self-modification audit trail is structured as an append-only hash chain:

```
┌────────────┐     ┌────────────┐     ┌────────────┐     ┌────────────┐
│ Contrib 0  │ --> │ Contrib 1  │ --> │ Contrib 2  │ --> │ Contrib 3  │
│            │     │            │     │            │     │            │
│ hash: H0   │     │ prev: H0   │     │ prev: H1   │     │ prev: H2   │
│ type: data │     │ hash: H1   │     │ hash: H2   │     │ hash: H3   │
│ review: OK │     │ type: arch │     │ type: data │     │ type: code │
│ sign: Ed.. │     │ review: OK │     │ review: OK │     │ review: OK │
└────────────┘     │ sign: Ed.. │     │ sign: Ed.. │     │ sign: Ed.. │
                   └────────────┘     └────────────┘     └────────────┘
```

Each contribution entry is individually signed and hash-linked, making insertion, deletion, or reordering of entries detectable.

### 3.5 Architecture Provenance

A model's architecture is a critical component of its identity. Unauthorized structural modifications (inserting backdoor layers, modifying attention patterns, adding covert channels) must be detectable.

#### 3.5.1 Architecture Manifest

```json
{
  "architecture_provenance": {
    "framework": "PyTorch 2.5",
    "architecture_class": "TransformerDecoderOnly",
    "architecture_definition_hash": "sha256:H(architecture.yaml)",
    "layer_manifest": [
      {
        "layer_id": "embedding",
        "type": "token_embedding",
        "config": {
          "vocab_size": 128256,
          "embedding_dim": 12288
        },
        "config_hash": "sha256:H(embedding_config)",
        "parameter_count": 1577009280
      },
      {
        "layer_id": "transformer_block_0",
        "type": "transformer_decoder_block",
        "config": {
          "hidden_size": 12288,
          "num_attention_heads": 96,
          "num_kv_heads": 8,
          "intermediate_size": 49152,
          "activation": "silu",
          "attention_type": "grouped_query_attention"
        },
        "config_hash": "sha256:H(block_0_config)",
        "parameter_count": 1207959552
      }
    ],
    "layer_manifest_merkle_root": "sha256:merkle_root_of_all_layer_configs",
    "total_layers": 128,
    "total_parameters": 175000000000,
    "training_code_hash": "sha256:H(training_pipeline_code)",
    "training_config": {
      "optimizer": "AdamW",
      "learning_rate_schedule": "cosine_with_warmup",
      "max_learning_rate": 3e-4,
      "batch_size": 4096,
      "total_training_tokens": 15000000000000,
      "config_hash": "sha256:H(training_config)"
    }
  }
}
```

#### 3.5.2 Architecture Integrity Verification

```python
def verify_architecture_integrity(
    model,
    birth_certificate: dict,
) -> ArchitectureReport:
    """
    Verify that a model's actual architecture matches its birth
    certificate's architecture provenance.

    Detects:
    - Added or removed layers
    - Modified layer configurations
    - Changed parameter counts
    - Unauthorized architectural alterations
    """
    cert_arch = birth_certificate["architecture_provenance"]
    issues = []

    # Extract actual architecture from the live model
    actual_layers = extract_layer_manifest(model)

    # Compare layer count
    if len(actual_layers) != cert_arch["total_layers"]:
        issues.append(
            ArchitectureIssue(
                severity="CRITICAL",
                message=f"Layer count mismatch: certificate says "
                        f"{cert_arch['total_layers']}, "
                        f"model has {len(actual_layers)}",
            )
        )

    # Compare each layer's configuration hash
    cert_layers = cert_arch["layer_manifest"]
    for i, (actual, expected) in enumerate(zip(actual_layers, cert_layers)):
        actual_config_hash = hashlib.sha256(
            canonicalize(actual["config"]).encode()
        ).hexdigest()

        if actual_config_hash != expected["config_hash"]:
            issues.append(
                ArchitectureIssue(
                    severity="CRITICAL",
                    message=f"Layer {i} ({expected['layer_id']}) config hash "
                            f"mismatch: expected {expected['config_hash'][:16]}..., "
                            f"got {actual_config_hash[:16]}...",
                )
            )

        if actual["parameter_count"] != expected["parameter_count"]:
            issues.append(
                ArchitectureIssue(
                    severity="HIGH",
                    message=f"Layer {i} parameter count mismatch: "
                            f"expected {expected['parameter_count']}, "
                            f"got {actual['parameter_count']}",
                )
            )

    # Verify layer manifest Merkle root
    actual_merkle_root = compute_merkle_root(
        [layer["config_hash"] for layer in actual_layers]
    )
    if actual_merkle_root != cert_arch["layer_manifest_merkle_root"]:
        issues.append(
            ArchitectureIssue(
                severity="CRITICAL",
                message="Layer manifest Merkle root mismatch---"
                        "architecture has been structurally modified",
            )
        )

    return ArchitectureReport(
        certificate_id=birth_certificate["certificate_id"],
        issues=issues,
        verdict="INTACT" if not issues else "TAMPERED",
    )
```

### 3.6 Generation Counter

The generation counter is a monotonically increasing integer that tracks how many rounds of recursive self-improvement a model has undergone. It is the most critical safety primitive in the birth certificate.

#### 3.6.1 Generation Counter Rules

1. **Monotonically increasing**: A model's generation MUST be strictly greater than or equal to the maximum generation of all its parent models. If any parent has a `self_referential_contributor` relationship, the generation MUST be strictly greater.
2. **Cryptographic chaining**: Each generation counter includes the hash of all previous generation counters in the chain, creating a tamper-evident history.
3. **Human oversight attestation**: Every generation increment MUST include a signed attestation from a human overseer confirming that human oversight was maintained during the self-improvement cycle.
4. **Threshold enforcement**: Organizations can define maximum generation thresholds beyond which additional governance is required.

#### 3.6.2 Generation Counter Enforcement

```python
def validate_generation_counter(
    birth_certificate: dict,
    certificate_registry,
) -> GenerationReport:
    """
    Validate that the generation counter is consistent with the
    model's lineage and that all required attestations are present.
    """
    gen_counter = birth_certificate["generation_counter"]
    claimed_gen = gen_counter["value"]
    issues = []

    # Compute expected generation from parent lineage
    parents = birth_certificate.get("parent_lineage", {}).get("parents", [])
    max_parent_gen = 0
    has_self_referential = False

    for parent in parents:
        parent_cert = certificate_registry.get(parent["certificate_id"])
        if parent_cert is None:
            issues.append("Cannot verify generation: parent certificate missing")
            continue

        parent_gen = parent_cert["generation_counter"]["value"]
        max_parent_gen = max(max_parent_gen, parent_gen)

        if parent["relationship"] in (
            "self_referential_contributor",
            "architecture_contributor",
        ):
            has_self_referential = True

    # Verify generation is consistent
    if has_self_referential:
        expected_min_gen = max_parent_gen + 1
        if claimed_gen < expected_min_gen:
            issues.append(
                f"Generation counter {claimed_gen} too low: "
                f"self-referential parent at gen {max_parent_gen} "
                f"requires minimum gen {expected_min_gen}"
            )
    else:
        if claimed_gen < max_parent_gen:
            issues.append(
                f"Generation counter {claimed_gen} below parent "
                f"generation {max_parent_gen}"
            )

    # Verify counter chain hash
    expected_chain_hash = compute_generation_chain_hash(
        birth_certificate, certificate_registry
    )
    if expected_chain_hash != gen_counter.get("counter_chain_hash"):
        issues.append("Generation counter chain hash is invalid---possible tampering")

    # Verify human oversight attestation
    oversight = gen_counter.get("human_oversight_attestation")
    if claimed_gen > 0 and oversight is None:
        issues.append(
            f"Generation {claimed_gen} requires human oversight attestation "
            f"but none was provided"
        )
    elif oversight:
        if not verify_ed25519_signature(
            oversight["attested_by"],
            oversight["attestation"],
            oversight.get("signature"),
        ):
            issues.append("Human oversight attestation signature is invalid")

    return GenerationReport(
        claimed_generation=claimed_gen,
        computed_minimum_generation=expected_min_gen if has_self_referential else max_parent_gen,
        has_self_referential_lineage=has_self_referential,
        human_oversight_verified=oversight is not None and not any(
            "oversight" in i for i in issues
        ),
        issues=issues,
        verdict="VALID" if not issues else "INVALID",
    )


def compute_generation_chain_hash(
    birth_certificate: dict,
    certificate_registry,
) -> str:
    """
    Compute the expected generation chain hash by walking the lineage
    back to generation 0 and chaining all generation values.

    chain_hash = H(gen_0_hash || gen_1_hash || ... || gen_N_value)
    """
    chain = []

    def _walk_generations(cert_id):
        cert = certificate_registry.get(cert_id)
        if cert is None:
            return
        gen = cert["generation_counter"]["value"]
        chain.append(f"{cert_id}:{gen}")
        prev = cert["generation_counter"].get("previous_generation_certificate")
        if prev:
            _walk_generations(prev)

    _walk_generations(birth_certificate["certificate_id"])
    chain.reverse()  # Oldest first

    chain_string = "||".join(chain)
    return hashlib.sha256(chain_string.encode()).hexdigest()
```

#### 3.6.3 Generation Threshold Policies

```json
{
  "generation_thresholds": {
    "unrestricted": {
      "max_generation": 1,
      "description": "Standard deployment---up to 1 generation of self-improvement",
      "requirements": ["birth_certificate", "human_oversight_attestation"]
    },
    "elevated_review": {
      "max_generation": 3,
      "description": "Enhanced governance---2-3 generations",
      "requirements": [
        "birth_certificate",
        "human_oversight_attestation",
        "safety_board_approval",
        "independent_capability_evaluation"
      ]
    },
    "restricted": {
      "max_generation": 5,
      "description": "Highly restricted---4-5 generations",
      "requirements": [
        "birth_certificate",
        "human_oversight_attestation",
        "safety_board_approval",
        "independent_capability_evaluation",
        "government_notification",
        "red_team_evaluation"
      ]
    },
    "prohibited_without_exception": {
      "max_generation": null,
      "description": "Beyond 5 generations---requires exceptional authorization",
      "requirements": [
        "All restricted requirements",
        "multi_government_approval",
        "international_oversight_body_review",
        "public_disclosure_of_capabilities"
      ]
    }
  }
}
```

### 3.7 C2PA Model Credentials Extension

The C2PA (Coalition for Content Provenance and Authenticity) standard provides "Content Credentials" for media---proving who created an image, video, or document. PAD-018 extends this framework from media to models.

#### 3.7.1 Conceptual Extension

```
C2PA Today:
    "Who made this IMAGE?"
    ┌──────────────────────────────────┐
    │  C2PA Manifest                   │
    │  ┌─────────────────────────┐     │
    │  │ Assertion: Author       │     │
    │  │ Assertion: Edit History │     │
    │  │ Assertion: AI Generated │     │
    │  └─────────────────────────┘     │
    │  Claim Signature (Ed25519)       │
    └──────────────────────────────────┘

C2PA Extended (PAD-018):
    "Who made this INTELLIGENCE?"
    ┌──────────────────────────────────────────────────┐
    │  C2PA Manifest                                   │
    │  ┌────────────────────────────────────────┐      │
    │  │ Assertion: vouch.model.birthCertificate│      │
    │  │ Assertion: vouch.model.trainingData    │      │
    │  │ Assertion: vouch.model.parentLineage   │      │
    │  │ Assertion: vouch.model.selfModLog      │      │
    │  │ Assertion: vouch.model.architecture    │      │
    │  │ Assertion: vouch.model.generation      │      │
    │  │ Assertion: vouch.model.fingerprint     │      │
    │  └────────────────────────────────────────┘      │
    │  Claim Signature (Ed25519)                       │
    └──────────────────────────────────────────────────┘
```

#### 3.7.2 C2PA Assertion Definitions

```json
{
  "c2pa_assertions": {
    "vouch.model.birthCertificate": {
      "label": "vouch.model.birthCertificate",
      "description": "Complete model birth certificate with lineage and provenance",
      "version": "1.0",
      "required": true,
      "content_type": "application/json",
      "schema_uri": "https://vouch-protocol.org/schemas/pad-018/birth-certificate/v1"
    },
    "vouch.model.trainingData": {
      "label": "vouch.model.trainingData",
      "description": "Training data provenance with Merkle root commitment",
      "version": "1.0",
      "required": true,
      "content_type": "application/json",
      "schema_uri": "https://vouch-protocol.org/schemas/pad-018/training-data/v1"
    },
    "vouch.model.parentLineage": {
      "label": "vouch.model.parentLineage",
      "description": "Signed DAG of parent model relationships",
      "version": "1.0",
      "required": true,
      "content_type": "application/json",
      "schema_uri": "https://vouch-protocol.org/schemas/pad-018/parent-lineage/v1"
    },
    "vouch.model.selfModLog": {
      "label": "vouch.model.selfModLog",
      "description": "Self-modification audit trail with safety review attestations",
      "version": "1.0",
      "required_when": "generation_counter > 0",
      "content_type": "application/json",
      "schema_uri": "https://vouch-protocol.org/schemas/pad-018/self-mod-log/v1"
    },
    "vouch.model.architecture": {
      "label": "vouch.model.architecture",
      "description": "Architecture manifest with layer-level Merkle tree",
      "version": "1.0",
      "required": true,
      "content_type": "application/json",
      "schema_uri": "https://vouch-protocol.org/schemas/pad-018/architecture/v1"
    },
    "vouch.model.generation": {
      "label": "vouch.model.generation",
      "description": "Recursive self-improvement generation counter with chain hash",
      "version": "1.0",
      "required": true,
      "content_type": "application/json",
      "schema_uri": "https://vouch-protocol.org/schemas/pad-018/generation/v1"
    },
    "vouch.model.fingerprint": {
      "label": "vouch.model.fingerprint",
      "description": "Behavioral fingerprint for post-signing tamper detection",
      "version": "1.0",
      "required": true,
      "content_type": "application/json",
      "schema_uri": "https://vouch-protocol.org/schemas/pad-018/fingerprint/v1"
    }
  }
}
```

#### 3.7.3 Embedding Birth Certificate in C2PA Manifest

```python
from c2pa import Builder, SignerInfo

def embed_birth_certificate_in_c2pa(
    model_file_path: str,
    birth_certificate: dict,
    signer_private_key_path: str,
    signer_certificate_path: str,
) -> str:
    """
    Embed a model birth certificate as a C2PA assertion in the
    model file's C2PA manifest.

    This extends C2PA from "content credentials" to "model credentials."
    """
    builder = Builder()

    # Add birth certificate as the primary assertion
    builder.add_assertion(
        label="vouch.model.birthCertificate",
        data=birth_certificate,
    )

    # Add individual components as separate assertions for granular access
    builder.add_assertion(
        label="vouch.model.trainingData",
        data=birth_certificate["training_data_provenance"],
    )
    builder.add_assertion(
        label="vouch.model.parentLineage",
        data=birth_certificate["parent_lineage"],
    )
    builder.add_assertion(
        label="vouch.model.architecture",
        data=birth_certificate["architecture_provenance"],
    )
    builder.add_assertion(
        label="vouch.model.generation",
        data=birth_certificate["generation_counter"],
    )
    builder.add_assertion(
        label="vouch.model.fingerprint",
        data=birth_certificate["model_identity"]["behavioral_fingerprint"],
    )

    if birth_certificate.get("self_modification_log", {}).get("self_referential"):
        builder.add_assertion(
            label="vouch.model.selfModLog",
            data=birth_certificate["self_modification_log"],
        )

    # Sign with Ed25519
    signer = SignerInfo(
        private_key_path=signer_private_key_path,
        certificate_path=signer_certificate_path,
        algorithm="Ed25519",
    )

    output_path = model_file_path + ".c2pa"
    builder.sign(signer, model_file_path, output_path)

    return output_path
```

### 3.8 Behavioral Fingerprinting

Binary hashes break under quantization, format conversion, and legitimate post-processing. Behavioral fingerprints provide a complementary identity mechanism that persists across these transformations.

#### 3.8.1 Stochastic Probe Fingerprinting

```python
def generate_behavioral_fingerprint(
    model,
    probe_set: list,
    n_samples_per_probe: int = 10,
    temperature: float = 0.0,
) -> BehavioralFingerprint:
    """
    Generate a behavioral fingerprint by running a standardized set
    of probe inputs and recording the model's output distribution.

    The probe set is designed to be:
    1. Diverse (covers many capability dimensions)
    2. Stable (produces consistent responses across runs at temp=0)
    3. Sensitive (small model changes produce detectable output changes)
    4. Non-gaming (probes are secret and rotated to prevent optimization)

    The fingerprint is a statistical summary, NOT the raw outputs---
    preventing reverse-engineering of model capabilities.
    """
    fingerprint_vectors = []

    for probe in probe_set:
        responses = []
        for _ in range(n_samples_per_probe):
            output = model.generate(
                prompt=probe.text,
                max_tokens=probe.max_tokens,
                temperature=temperature,
            )
            responses.append(output)

        # Extract statistical features (NOT raw text)
        vector = extract_fingerprint_features(responses, probe)
        fingerprint_vectors.append(vector)

    # Combine into single fingerprint
    combined = aggregate_fingerprint_vectors(fingerprint_vectors)

    return BehavioralFingerprint(
        method="vouch:fingerprint:stochastic-probe-v1",
        fingerprint_hash=hashlib.sha256(
            combined.tobytes()
        ).hexdigest(),
        probe_set_hash=hashlib.sha256(
            canonicalize([p.to_dict() for p in probe_set]).encode()
        ).hexdigest(),
        timestamp=iso_timestamp(),
        feature_dimensionality=len(combined),
        n_probes=len(probe_set),
    )


def extract_fingerprint_features(responses: list, probe) -> list:
    """
    Extract statistical features from model responses that are
    robust to minor variations but sensitive to model changes.
    """
    features = []

    # Token-level statistics
    token_lengths = [len(r.tokens) for r in responses]
    features.extend([
        float(sum(token_lengths)) / len(token_lengths),  # mean length
        float(max(token_lengths) - min(token_lengths)),   # length variance
    ])

    # Top-token agreement across samples
    if len(responses) > 1:
        first_tokens = [r.tokens[0] if r.tokens else None for r in responses]
        agreement = len(set(first_tokens)) / len(first_tokens)
        features.append(agreement)

    # Logit-based features (if available)
    if hasattr(responses[0], "logprobs") and responses[0].logprobs:
        avg_logprobs = []
        for r in responses:
            avg_logprobs.append(
                sum(r.logprobs) / len(r.logprobs) if r.logprobs else 0.0
            )
        features.append(float(sum(avg_logprobs)) / len(avg_logprobs))

    # Semantic consistency (embedding similarity of responses)
    if len(responses) >= 2:
        embeddings = [embed(r.text) for r in responses]
        pairwise_sim = average_pairwise_cosine_similarity(embeddings)
        features.append(pairwise_sim)

    return features
```

#### 3.8.2 Tamper Detection via Fingerprint Comparison

```python
def detect_model_tampering(
    model,
    birth_certificate: dict,
    probe_set: list,
    threshold: float = 0.15,
) -> TamperReport:
    """
    Compare a model's current behavioral fingerprint against its
    birth certificate's fingerprint to detect post-signing tampering.

    Detects:
    - Unauthorized fine-tuning
    - Weight manipulation / backdoor insertion
    - Model replacement (different model using same certificate)
    - Quantization beyond declared precision
    """
    # Generate current fingerprint
    current_fp = generate_behavioral_fingerprint(model, probe_set)

    # Retrieve expected fingerprint from birth certificate
    expected_fp_hash = birth_certificate["model_identity"]["behavioral_fingerprint"]["fingerprint_hash"]

    # Regenerate expected fingerprint for comparison
    # (In practice, the full fingerprint vector would be stored
    #  in a secure registry, with only the hash in the certificate)
    expected_fp = fingerprint_registry.get(expected_fp_hash)

    if expected_fp is None:
        return TamperReport(
            verdict="UNVERIFIABLE",
            message="Expected fingerprint not found in registry",
        )

    # Compute behavioral distance
    distance = compute_fingerprint_distance(current_fp, expected_fp)

    if distance > threshold:
        return TamperReport(
            verdict="TAMPERED",
            distance=distance,
            threshold=threshold,
            message=f"Behavioral distance {distance:.4f} exceeds "
                    f"threshold {threshold:.4f}---model has been modified "
                    f"since birth certificate was issued",
            likely_cause=diagnose_tampering(current_fp, expected_fp),
        )

    return TamperReport(
        verdict="AUTHENTIC",
        distance=distance,
        threshold=threshold,
        message=f"Behavioral distance {distance:.4f} within "
                f"threshold {threshold:.4f}---model appears unmodified",
    )


def diagnose_tampering(current_fp, expected_fp) -> str:
    """
    Analyze fingerprint divergence patterns to suggest the likely
    cause of tampering.
    """
    divergence_pattern = compute_per_dimension_divergence(current_fp, expected_fp)

    if divergence_pattern.uniform_shift:
        return "QUANTIZATION: Uniform behavioral shift suggests precision reduction"
    elif divergence_pattern.localized_spike:
        return "FINE_TUNING: Localized capability change suggests targeted fine-tuning"
    elif divergence_pattern.global_divergence:
        return "REPLACEMENT: Complete behavioral change suggests model substitution"
    elif divergence_pattern.subtle_targeted:
        return "BACKDOOR: Subtle, targeted behavioral change in specific domains"
    else:
        return "UNKNOWN: Divergence pattern does not match known tampering signatures"
```

### 3.9 Lineage Verification at Inference Time

The ultimate goal is for verifiers to check a model's birth certificate BEFORE accepting its outputs, creating a trust gateway between model provenance and output validity.

#### 3.9.1 Inference-Time Verification Flow

```
┌──────────┐                                           ┌──────────────┐
│          │  1. Request + Agent Vouch Token            │              │
│  Client  │ ----------------------------------------> │   AI Agent   │
│          │                                           │   (Model X)  │
│          │  2. Response + Vouch Token                │              │
│          │     + Model Birth Certificate Reference   │              │
│          │ <---------------------------------------- │              │
└────┬─────┘                                           └──────────────┘
     │
     │  3. Verify agent identity (PAD-001)
     │  4. Verify delegation chain (PAD-002)
     │  5. Verify reasoning (PAD-017)
     │
     │  6. Resolve model birth certificate
     │
     ▼
┌──────────────────┐     7. Fetch certificate     ┌───────────────────┐
│  Birth Cert      │ <--------------------------- │  Certificate      │
│  Verifier        │                               │  Registry         │
│                  │     8. Verify:                │                   │
│  - Signature OK? │        - Training data legal? │                   │
│  - Lineage OK?   │        - Generation within   │                   │
│  - Fingerprint?  │          policy threshold?    │                   │
│  - Generation?   │        - Architecture intact? │                   │
│  - Not tampered? │        - Parents verified?    │                   │
└────────┬─────────┘                               └───────────────────┘
         │
         │  9. Lineage Verdict
         │
    ┌────▼────┐         ┌────────────┐
    │ ACCEPT  │         │  REJECT    │
    │ output  │         │  output    │
    └─────────┘         └────────────┘
```

#### 3.9.2 Vouch Token Extension for Model Provenance

The Vouch Token (PAD-001) is extended with a model provenance field:

```json
{
  "vouch": {
    "version": "1.0",
    "payload": {
      "action": "generate_response",
      "content_hash": "sha256:H(response_content)",
      "model_provenance": {
        "birth_certificate_id": "vouch:model:bc-2026-02-14-a8f3d1e7...",
        "birth_certificate_hash": "sha256:H(full_birth_certificate)",
        "model_did": "did:key:z6MkModel...",
        "generation": 3,
        "fingerprint_hash": "sha256:H(behavioral_fingerprint)",
        "certificate_registry": "https://registry.vouch-protocol.org/certificates/"
      }
    },
    "signature": "ed25519:agent_signs_payload"
  }
}
```

#### 3.9.3 Verification Policy Engine

```python
def verify_model_provenance_at_inference(
    vouch_token: dict,
    verification_policy: dict,
    certificate_registry,
) -> InferenceVerdict:
    """
    Verify a model's provenance before accepting its output.

    The verification policy defines what the verifier requires:
    - Maximum generation allowed
    - Required training data attestations
    - Banned parent models
    - Required safety reviews
    """
    model_prov = vouch_token["vouch"]["payload"].get("model_provenance")

    if model_prov is None:
        if verification_policy.get("require_model_provenance", False):
            return InferenceVerdict(
                accept=False,
                reason="Model provenance required by policy but not provided",
            )
        return InferenceVerdict(accept=True, reason="No provenance required")

    # Fetch and verify birth certificate
    cert_id = model_prov["birth_certificate_id"]
    birth_cert = certificate_registry.get(cert_id)

    if birth_cert is None:
        return InferenceVerdict(
            accept=False,
            reason=f"Birth certificate {cert_id} not found in registry",
        )

    # Verify certificate signature
    if not verify_certificate_signature(birth_cert):
        return InferenceVerdict(
            accept=False,
            reason="Birth certificate signature verification failed",
        )

    # Verify certificate hash matches token claim
    cert_hash = hashlib.sha256(canonicalize(birth_cert).encode()).hexdigest()
    if cert_hash != model_prov["birth_certificate_hash"]:
        return InferenceVerdict(
            accept=False,
            reason="Birth certificate hash does not match token claim",
        )

    # Policy enforcement
    issues = []

    # 1. Generation limit
    max_gen = verification_policy.get("max_generation")
    if max_gen is not None:
        actual_gen = birth_cert["generation_counter"]["value"]
        if actual_gen > max_gen:
            issues.append(
                f"Model generation {actual_gen} exceeds policy "
                f"maximum {max_gen}"
            )

    # 2. Required training data attestations
    required_attestations = verification_policy.get("required_attestations", [])
    cert_attestations = birth_cert.get(
        "training_data_provenance", {}
    ).get("data_governance_attestation", {})
    for req in required_attestations:
        if req not in cert_attestations:
            issues.append(f"Required attestation '{req}' missing")

    # 3. Banned parent models
    banned_parents = verification_policy.get("banned_parents", [])
    parents = birth_cert.get("parent_lineage", {}).get("parents", [])
    for parent in parents:
        if parent["certificate_id"] in banned_parents:
            issues.append(
                f"Parent model {parent['certificate_id']} is banned by policy"
            )

    # 4. Self-modification safety reviews
    if birth_cert.get("self_modification_log", {}).get("self_referential"):
        contributions = birth_cert["self_modification_log"].get("contributions", [])
        for contrib in contributions:
            review = contrib.get("safety_review")
            if review is None:
                issues.append(
                    f"Self-modification contribution {contrib['contribution_id']} "
                    f"lacks safety review"
                )
            elif review["verdict"] not in ("APPROVED", "APPROVED_WITH_CONDITIONS"):
                issues.append(
                    f"Self-modification contribution {contrib['contribution_id']} "
                    f"failed safety review: {review['verdict']}"
                )

    # 5. Fingerprint freshness
    fp_timestamp = birth_cert["model_identity"]["behavioral_fingerprint"]["timestamp"]
    max_fingerprint_age = verification_policy.get("max_fingerprint_age_days", 90)
    if fingerprint_age_days(fp_timestamp) > max_fingerprint_age:
        issues.append(
            f"Behavioral fingerprint is {fingerprint_age_days(fp_timestamp)} "
            f"days old (policy maximum: {max_fingerprint_age})"
        )

    if issues:
        return InferenceVerdict(
            accept=False,
            reason="Policy violations: " + "; ".join(issues),
            issues=issues,
        )

    return InferenceVerdict(
        accept=True,
        reason="Model provenance verified and compliant with policy",
        certificate_id=cert_id,
        generation=birth_cert["generation_counter"]["value"],
    )
```

### 3.10 Adversarial Scenarios and Mitigations

#### 3.10.1 Forged Birth Certificate

**Attack**: An adversary creates a fake birth certificate for a model, claiming clean lineage and low generation count.

**Mitigation**: Birth certificates MUST be signed by recognized certificate issuers (labs, auditors) whose Ed25519 public keys are registered in a trust store. Verifiers only accept certificates from trusted issuers. The certificate issuer's reputation is at stake.

```python
TRUSTED_ISSUERS = {
    "did:key:z6MkLabA...": {"name": "Lab A", "trust_level": "high"},
    "did:key:z6MkLabB...": {"name": "Lab B", "trust_level": "high"},
    "did:key:z6MkAudit...": {"name": "Independent Auditor", "trust_level": "medium"},
}

def verify_issuer_trust(birth_certificate: dict) -> bool:
    signer_did = birth_certificate["signature"]["signer_did"]
    return signer_did in TRUSTED_ISSUERS
```

#### 3.10.2 Concealed Self-Improvement Generation

**Attack**: A lab trains a Generation 5 model but labels it Generation 1 to avoid governance restrictions.

**Mitigation**: The generation counter chain hash links back to all prior generations. To fake Generation 1, the attacker would need to produce a valid chain hash that includes only one generation, but the actual parent certificates (which are independently stored in the registry) would reveal the true lineage. Additionally, behavioral fingerprinting would detect capability jumps inconsistent with the claimed generation.

#### 3.10.3 Training Data Laundering

**Attack**: A lab trains on stolen data but commits a Merkle root for a "clean" dataset.

**Mitigation**: Inclusion proofs can be demanded by data owners. If a data owner suspects their content was used, they can request an inclusion proof. The lab must either produce a valid inclusion proof (confirming usage) or the data owner can perform independent testing (memorization probes) and compare results against the claimed exclusion.

#### 3.10.4 Post-Signing Model Modification

**Attack**: An adversary fine-tunes a model (inserting a backdoor) but presents the original birth certificate.

**Mitigation**: Behavioral fingerprinting detects behavioral changes. The verifier runs the standardized probe set against the model and compares the behavioral fingerprint to the one in the birth certificate. Backdoor insertion changes behavior, which changes the fingerprint.

#### 3.10.5 Fingerprint Evasion

**Attack**: An adversary modifies the model in a way that preserves the behavioral fingerprint on known probes but alters behavior on specific trigger inputs (i.e., a "sleeper" backdoor).

**Mitigation**: This is acknowledged as a fundamental limitation. Mitigations include: (1) rotating and expanding probe sets over time, (2) keeping probe sets secret, (3) combining behavioral fingerprinting with architecture integrity verification (which would detect added layers), and (4) requiring periodic re-fingerprinting with new probe sets (integration with PAD-016 Heartbeat Protocol).

#### 3.10.6 Certificate Replay

**Attack**: An adversary presents a legitimate birth certificate from Model A when actually serving Model B.

**Mitigation**: The verifier requests both the birth certificate AND a live behavioral fingerprint check. Since the fingerprint is tied to the specific model, Model B cannot produce Model A's fingerprint.

---

## 4. Integration with Vouch Protocol Ecosystem

### 4.1 PAD-001 Integration (Agent Identity)

PAD-001 provides cryptographic identity for AI agents. PAD-018 extends this by giving the underlying MODEL its own identity:

```
PAD-001: Agent Identity          PAD-018: Model Identity
┌───────────────────────┐        ┌───────────────────────┐
│ Agent DID             │        │ Model DID             │
│ Agent Public Key      │  links │ Birth Certificate     │
│ Agent Vouch Token     │ -----> │ Generation Counter    │
│ Agent Delegation      │   to   │ Training Provenance   │
└───────────────────────┘        └───────────────────────┘

Combined: An agent's Vouch Token now includes both
WHO is acting (agent DID) and WHAT is powering it (model DID).
```

### 4.2 PAD-002 Integration (Chain of Custody)

PAD-002's delegation chains can now include model-level constraints:

```json
{
  "delegation": {
    "sub": "did:web:alice.com",
    "aud": "did:web:agent.service.com",
    "intent": "Analyze financial reports",
    "model_requirements": {
      "max_generation": 2,
      "required_attestations": ["bias_audit", "copyright_review"],
      "banned_lineage": ["vouch:model:bc-known-problematic..."],
      "require_birth_certificate": true
    }
  }
}
```

This means Alice can delegate to an agent but constrain WHICH MODELS the agent is permitted to use---a new dimension of delegation authority.

### 4.3 PAD-012 Integration (Vouch Covenant)

PAD-012's covenants (machine-executable usage policies) can be extended to govern model usage:

```json
{
  "covenant": {
    "asset_type": "ai_model",
    "model_certificate_id": "vouch:model:bc-2026-02-14-a8f3d1e7...",
    "usage_rights": {
      "inference": "allow",
      "fine_tuning": "require(license_agreement, model_creator)",
      "distillation": "forbidden",
      "weight_extraction": "forbidden",
      "deployment_regions": ["US", "EU", "UK"],
      "max_downstream_generations": 1
    }
  }
}
```

This creates enforceable "terms of use" that travel with the model---the covenant is embedded in the C2PA manifest alongside the birth certificate.

### 4.4 PAD-016 Integration (Heartbeat Protocol)

Models require periodic re-attestation via the Heartbeat Protocol:

```json
{
  "heartbeat": {
    "agent_did": "did:key:z6MkAgent...",
    "model_provenance_digest": {
      "model_did": "did:key:z6MkModel...",
      "birth_certificate_id": "vouch:model:bc-2026-02-14-a8f3d1e7...",
      "current_fingerprint_hash": "sha256:H(current_behavioral_fingerprint)",
      "fingerprint_drift": 0.03,
      "last_full_verification": "2026-02-10T00:00:00Z",
      "generation": 3
    }
  }
}
```

If `fingerprint_drift` exceeds a threshold between heartbeats, the model may have been swapped or modified---triggering re-verification or credential denial.

---

## 5. Claims and Novel Contributions

### Claim 1: Model Birth Certificate with Cryptographic Lineage Binding
A method for issuing a cryptographically signed "birth certificate" for an AI model that binds the model's identity (DID, binary hash, behavioral fingerprint) to its verifiable lineage (training data provenance, parent model graph, self-modification history, architecture definition), creating a single tamper-evident artifact that answers "what is this model, where did it come from, and what made it."

### Claim 2: Training Data Merkle Root with Inclusion and Exclusion Proofs
A method for committing to a training dataset via a Merkle root that enables two complementary proof types: inclusion proofs (demonstrating a specific data item WAS in the training set, for licensing compliance and opt-out enforcement) and exclusion proofs (demonstrating a specific data item was NOT in the training set, for legal defense against copyright claims)---without requiring disclosure of the full dataset.

### Claim 3: Parent Model Lineage as Signed Directed Acyclic Graph
A method for recording AI model lineage as a cryptographically signed directed acyclic graph where each node is a model birth certificate and edges represent typed relationships (base model, fine-tune source, distillation teacher, merge contributor, self-referential contributor), enabling verifiable traversal of the complete model family tree.

### Claim 4: Self-Modification Audit Trail with Mandatory Safety Attestation
A method for maintaining an append-only, hash-chained audit trail of a model's contributions to its own training or architecture, where each contribution entry includes a typed description, a hash of the contributed artifact, and a mandatory safety review attestation signed by human reviewers---creating an unbroken chain of accountability for recursive self-improvement.

### Claim 5: Cryptographic Architecture Provenance with Layer-Level Merkle Tree
A method for binding a model's architecture definition to its birth certificate through a layer-level Merkle tree where each leaf is the configuration hash of a single layer, enabling detection of unauthorized structural modifications (added layers, changed attention patterns, modified activation functions) without requiring access to model weights.

### Claim 6: Monotonically Increasing Generation Counter with Chain Hash
A method for tracking recursive self-improvement generations via a monotonically increasing counter that is cryptographically chained to all prior generation counters, making it computationally infeasible to conceal the true depth of a model's self-improvement lineage---combined with mandatory human oversight attestation at each generation increment.

### Claim 7: C2PA Extension from Content Credentials to Model Credentials
A method for extending the C2PA Content Credentials standard to AI models by defining new assertion types (vouch.model.birthCertificate, vouch.model.trainingData, vouch.model.parentLineage, vouch.model.selfModLog, vouch.model.architecture, vouch.model.generation, vouch.model.fingerprint) that embed model provenance within the existing C2PA manifest framework---extending "who made this media" to "who made this intelligence."

### Claim 8: Behavioral Fingerprinting via Stochastic Probe Analysis
A method for generating a behavioral fingerprint of an AI model by running a standardized, secret probe set and recording statistical features of the model's output distribution, where the resulting fingerprint persists across quantization and format conversion and can detect post-signing tampering including unauthorized fine-tuning, weight manipulation, backdoor insertion, and model substitution.

### Claim 9: Inference-Time Lineage Verification
A method for verifying a model's birth certificate at inference time, where the model's Vouch Token includes a reference to its birth certificate, and the verifier checks the certificate's signature, lineage integrity, generation counter, training data attestations, and behavioral fingerprint against a verification policy before accepting the model's output---creating a trust gateway between model provenance and output validity.

### Claim 10: Generation Threshold Policy Enforcement
A system of tiered governance thresholds indexed by recursive self-improvement generation count, where increasing generation numbers trigger escalating oversight requirements (safety board approval, independent capability evaluation, government notification, red team evaluation), enforceable at inference time through birth certificate verification.

### Claim 11: Training Data Governance Attestation Binding
A method for binding third-party governance attestations (consent audits, copyright reviews, bias audits) to the training data Merkle root within a model's birth certificate, where each attestation is independently signed by the auditor and verifiable against the same Merkle root, creating a chain of accountability from data governance through training to deployed model.

### Claim 12: Model-Level Delegation Constraints in Agent Authorization
A method for extending delegation chains (PAD-002) with model-level constraints that restrict which models an agent is permitted to use, including maximum generation limits, required attestations, and banned lineage---enabling delegators to control not only WHAT an agent does but WHAT POWERS it.

### Claim 13: Self-Modification Risk Classification with Escalating Oversight
A taxonomy of self-modification types (synthetic training data, architecture suggestion, hyperparameter optimization, training code modification, evaluation criteria, reward signal modification) mapped to risk levels with escalating oversight requirements---from automated review with human spot-checking for medium-risk to mandatory full human review with board approval for critical-risk modifications.

### Claim 14: Cross-Certificate Fingerprint Drift Detection via Heartbeat Integration
A method for detecting model swapping or unauthorized modification between heartbeat intervals (PAD-016) by including behavioral fingerprint drift measurements in the heartbeat digest, where drift exceeding a threshold triggers re-verification or credential denial---enabling continuous model integrity monitoring without continuous full verification.

---

## 6. Prior Art Differentiation

| Existing Approach | What It Does | Limitation | PAD-018 Advancement |
|---|---|---|---|
| **Model Cards** (Mitchell et al., 2019) | Human-readable documentation of model properties | Unstructured text; no cryptographic binding; easily fabricated or outdated | Cryptographically signed birth certificate with verifiable Merkle proofs for every claim |
| **HuggingFace Model Metadata** | JSON metadata accompanying model files on Hub | Not signed; no lineage graph; trivially editable by anyone with repo access | Ed25519-signed lineage DAG with chain-of-custody back to root ancestors |
| **MLflow Model Registry** | Tracks model experiments, versions, and deployments | Tracks experiments, not lineage; no cryptographic binding; single-org scope | Cross-organizational cryptographic lineage with Merkle-rooted training data provenance |
| **Weights & Biases Artifacts** | Tracks model artifacts and their dependencies | Dependency tracking, not cryptographic lineage; no generation counters; no self-modification audit | Generation counter with chain hash; self-modification audit trail with safety attestations |
| **SLSA (Supply-chain Levels for Software Artifacts)** | Provenance for software build pipelines | Designed for deterministic software builds; does not address non-deterministic training, behavioral identity, or recursive self-improvement | Model-specific provenance addressing training non-determinism, behavioral fingerprinting, and generation tracking |
| **Sigstore / cosign** | Keyless signing for container images and software | Signs binary artifacts; model identity transcends binary identity (quantization, distillation); no lineage graph | Behavioral fingerprints that persist across format changes; lineage DAG with relationship typing |
| **SBOM (Software Bill of Materials)** | Lists software dependencies | Lists components, not training data; no Merkle proofs; no exclusion proof capability | Training data Merkle tree with inclusion AND exclusion proofs for legal compliance |
| **C2PA Content Credentials** | Provenance for images, video, audio, documents | Covers media provenance; no assertion types for model architecture, training data, or generation counter | New C2PA assertion types extending content credentials to model credentials |
| **Datasheets for Datasets** (Gebru et al., 2021) | Documentation of dataset properties | Documentation only; no cryptographic commitment; no proof of use or non-use | Merkle-rooted dataset commitment with cryptographic inclusion/exclusion proofs |

**Core differentiator**: No existing system provides cryptographic model lineage that addresses all of: training data provenance with inclusion/exclusion proofs, parent model lineage as a signed DAG, self-modification audit trails with safety attestations, architecture provenance, generation counting for recursive self-improvement, behavioral fingerprinting, C2PA integration, and inference-time verification. Each individual component has loose analogues; the combination and the specific application to recursive self-improvement governance is novel.

---

## 7. Use Cases

### 7.1 Regulatory Compliance: EU AI Act Model Transparency

The EU AI Act requires transparency about high-risk AI systems including their training data and development process. A model's birth certificate provides machine-verifiable compliance:

- **Training data provenance**: Auditors verify the Merkle root against the lab's claimed dataset; data owners verify inclusion/exclusion of their content.
- **Lineage graph**: Regulators verify that no banned models (e.g., from sanctioned entities) appear in the lineage.
- **Generation counter**: Regulators enforce maximum generation thresholds for deployment in critical sectors.

### 7.2 Model Marketplace Trust

An enterprise purchasing model access from a third-party provider wants assurance about the model's provenance:

- Before integrating the model, the enterprise's verification policy engine checks the birth certificate: Is the generation within acceptable limits? Are required training data attestations present? Does the behavioral fingerprint match?
- The enterprise's delegation chain (PAD-002) includes model-level constraints: "This agent may only use models with Generation <= 2 and a valid copyright review attestation."

### 7.3 Open-Source Model Provenance

An open-source model released on a public hub includes a C2PA manifest with its birth certificate. Downstream users can:

- Verify the model was actually released by the claimed organization (Ed25519 signature verification).
- Verify the training data did not include specific copyrighted material (exclusion proof).
- Verify the model's architecture has not been modified since release (architecture Merkle root).
- Track the model's lineage through fine-tuning, distillation, and merging by the community.

### 7.4 Recursive Self-Improvement Governance

A frontier lab's internal policy requires that any model beyond Generation 3 undergoes safety board review. The birth certificate protocol enforces this:

- The generation counter automatically increments when a model contributes to its own successor.
- The counter chain hash makes it impossible to reset or decrement the counter.
- The human oversight attestation requirement ensures a human signs off on each generation.
- External auditors can independently verify the generation count and safety review chain.

### 7.5 Incident Forensics: Model Attribution

After an AI system causes significant harm, investigators need to determine which specific model was responsible:

- The agent's Vouch Token includes a model provenance reference pointing to the birth certificate.
- The birth certificate reveals the model's complete lineage, training data, and generation.
- Behavioral fingerprinting confirms whether the model at incident time matches the claimed certificate.
- The self-modification audit trail reveals whether the model had any self-referential training that might explain the harmful behavior.

### 7.6 Model Supply Chain Security

A defense contractor requires that AI models used in critical infrastructure have verified provenance:

- Birth certificates are checked against a trust store of approved issuers.
- Lineage graphs are traversed to ensure no foreign-origin models appear in the chain.
- Architecture integrity verification confirms no unauthorized modifications.
- Periodic re-fingerprinting via the Heartbeat Protocol (PAD-016) ensures ongoing model integrity.

---

## 8. Security Considerations

### 8.1 Threat Model

| Threat | Attack Vector | Countermeasure | Residual Risk |
|---|---|---|---|
| **Forged birth certificate** | Adversary creates fake certificate | Ed25519 signatures from trusted issuers; issuer trust store | Compromised issuer key |
| **Concealed generation** | Lab undercounts generation to avoid governance | Chain hash linking all generations; independent fingerprint analysis for capability jumps | Collusion between lab and all parent certificate holders |
| **Training data laundering** | Train on stolen data, commit clean Merkle root | Inclusion proofs for data owners; memorization testing; sorted Merkle exclusion proofs | Attacker trains separate "clean" model for proofs while deploying "dirty" model |
| **Post-signing modification** | Fine-tune or backdoor model after certification | Behavioral fingerprinting; architecture integrity verification; periodic re-attestation | Sleeper backdoors activated by rare triggers that evade probe sets |
| **Certificate replay** | Present Model A's certificate for Model B | Live behavioral fingerprint check at verification time | Adversary trains Model B to mimic Model A's fingerprint on known probes |
| **Probe set leakage** | Adversary obtains behavioral fingerprint probe set | Secret, rotated probe sets; multiple probe set generations | Adversary with ongoing access to probe sets can train to evade each new set |
| **Registry compromise** | Adversary modifies certificates in the registry | Registry entries are signed; clients verify signatures independently of registry | Compromised registry + compromised issuer key (multi-factor compromise) |
| **Lineage graph poisoning** | Adversary inserts false parent relationships | Parent certificate hashes must match; parent certificates must exist and verify | If adversary controls parent certificate issuance, they can construct false lineage |

### 8.2 Cryptographic Requirements

1. **All signatures MUST use Ed25519.** RSA and ECDSA are NOT permitted for birth certificate signatures to maintain consistency with the Vouch Protocol ecosystem.
2. **Hash function**: SHA-256 for all Merkle trees and hash commitments.
3. **Canonical serialization**: Deterministic JSON (sorted keys, no whitespace) for all signed payloads.
4. **Key management**: Birth certificate signing keys SHOULD be stored in HSMs. Compromise of a signing key invalidates all certificates issued with that key.
5. **Timestamp authority**: Birth certificate timestamps SHOULD be independently attested by a trusted timestamp authority (RFC 3161) to prevent backdating.

### 8.3 Privacy Considerations

1. **Training data**: Merkle proofs reveal the existence or absence of specific data items without exposing the full dataset. Labs retain privacy over their training data composition while enabling targeted verification.
2. **Architecture**: The architecture manifest reveals high-level structure but not proprietary implementation details (custom kernels, optimization techniques).
3. **Behavioral fingerprints**: Fingerprints are statistical summaries, not raw model outputs. They cannot be used to extract model capabilities or reproduce model behavior.
4. **Lineage graphs**: Parent model relationships are public within the certificate. If lineage confidentiality is required, the certificate can reference parent certificates by hash without naming them, with full lineage available only to authorized auditors.

### 8.4 Limitations

1. **Voluntary adoption**: This protocol cannot force labs to issue honest birth certificates. Its value depends on ecosystem adoption and the business/regulatory incentive to participate.
2. **Behavioral fingerprint arms race**: As fingerprinting techniques improve, adversaries will develop evasion techniques. The probe set must be continuously updated.
3. **Computational cost of lineage verification**: Deep lineage graphs (Generation 10+) require traversal of potentially thousands of certificates. Caching and checkpoint verification are necessary for practical deployment.
4. **Non-deterministic training**: Two training runs with identical inputs produce different models. Birth certificates attest to the PROCESS and INPUTS, not to a guaranteed OUTPUT model.
5. **Retroactive application**: Models already deployed without birth certificates cannot be retroactively certified with full provenance. They can receive partial certificates with a `provenance_gap: true` flag indicating incomplete lineage.

---

## 9. Conclusion

The Birth Certificate Protocol closes the critical gap between agent-level provenance (who is acting) and model-level provenance (what powers the actor). As AI systems increasingly participate in their own creation, cryptographic model lineage transitions from a governance nicety to a safety necessity.

The protocol's generation counter with chain hash makes it computationally infeasible to conceal the depth of recursive self-improvement---an increasingly important safety property as the interval between model generations compresses. The training data Merkle root with inclusion and exclusion proofs provides the cryptographic foundation for data governance compliance. The behavioral fingerprinting system detects post-signing tampering that binary hashing alone cannot catch. The C2PA extension brings model provenance into the existing content credentials ecosystem, leveraging established infrastructure rather than building parallel systems.

Critically, the protocol is designed for the adversarial reality that not all actors will participate honestly. Every component includes explicit threat analysis and mitigations for the scenario where the model creator, the model deployer, or the model itself is attempting to deceive. The birth certificate is not a trust-me document---it is a verify-me artifact.

The combination of training data provenance, parent lineage graphs, self-modification audit trails, architecture integrity, generation counting, behavioral fingerprinting, and inference-time verification creates a defense-in-depth approach where compromising model provenance requires simultaneously defeating multiple independent verification mechanisms.

AI is now building AI. The Birth Certificate Protocol ensures we never lose track of who built what, from what, and how many times the process has recursed.

---

## 10. References

- Mitchell, M. et al., "Model Cards for Model Reporting" (FAT* 2019)
- Gebru, T. et al., "Datasheets for Datasets" (Communications of the ACM, 2021)
- OpenAI, "GPT-5 System Card" (2025)---disclosure of model self-contribution to training
- C2PA Technical Specification, Version 2.1 (Coalition for Content Provenance and Authenticity)
- SLSA: Supply-chain Levels for Software Artifacts, https://slsa.dev
- Sigstore: Software Supply Chain Security, https://sigstore.dev
- Merkle, R., "A Digital Signature Based on a Conventional Encryption Function" (CRYPTO 1987)
- RFC 3161: Internet X.509 PKI Time-Stamp Protocol
- NIST AI Risk Management Framework (AI RMF 1.0), 2023
- ISO/IEC 42001:2023 Artificial Intelligence Management System
- EU Artificial Intelligence Act, Regulation (EU) 2024/1689
- Hubinger, E. et al., "Sleeper Agents: Training Deceptive LLMs That Persist Through Safety Training" (Anthropic, 2024)
- Vouch Protocol Prior Art Disclosures:
  - PAD-001: Cryptographic Binding of AI Agent Identity
  - PAD-002: Cryptographic Binding of AI Agent Intent via Recursive Delegation
  - PAD-012: Method for Embedding Executable Usage Covenants in Media Provenance Manifests
  - PAD-016: Method for Continuous Trust Maintenance via Dynamic Credential Renewal
  - PAD-017: Method for Cryptographic Proof of Reasoning with Adaptive Commitment Depth

---

*This document is published as prior art to prevent patent assertion on the described concepts while allowing free use by the community under the Apache 2.0 license.*
