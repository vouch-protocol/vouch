# PAD-035: Asynchronous Chunked Verification and Edge-Optimized Post-Quantum Signatures

**Identifier:** PAD-035
**Title:** Method for Progressive Post-Quantum Signature Verification via HTTP/2 Streamed Chunks and Hardware-Accelerated Lattice Sampling on Edge Devices
**Publication Date:** April 22, 2026
**Prior Art Effective Date:** April 22, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Post-Quantum Cryptography / Edge Computing / HTTP Transport / Hardware Acceleration / Agent Identity
**Author:** Ramprasad Anandam Gaddam
**Related:** PAD-001 (Cryptographic Agent Identity), PAD-025 (Edge-First Content Provenance), PAD-033 (ZK PQ Signature Compression), PAD-034 (Composite Threshold Swarm Consensus)

---

## 1. Abstract

A suite of transport-layer and hardware-optimized methods for deploying post-quantum signatures on resource-constrained AI agents and latency-sensitive web protocols. The disclosure addresses two distinct but complementary problems: massive signature sizes that exceed single-transmission capacity (SPHINCS+ at 7,856-49,856 bytes), and high memory requirements that prevent post-quantum key generation on edge devices (ML-DSA requiring 150KB+ working memory for NTT operations). The system introduces two novel protocol variants:

**Variant A: Stateless Streaming Verification (SPHINCS+ over HTTP/2)**

A progressive verification protocol where massive hash-based signatures are sliced into authenticated chunks transmitted across HTTP/2 multiplexed streams. A lightweight classical signature (secp256k1 or Ed25519) provides immediate low-trust authorization for time-sensitive operations, while SPHINCS+ chunks are asynchronously streamed, reconstructed, and verified in the background to achieve final cryptographic settlement. The protocol introduces a **dual-trust-level execution model**: agents can begin executing low-risk operations immediately under classical trust, while high-risk operations are gated behind full SPHINCS+ verification.

**Variant B: Ultra-Edge Falcon-Lite (GPU-Accelerated Lattice Sampling)**

A hardware-optimized post-quantum signature scheme that pairs a classical elliptic curve signature with a memory-constrained variant of the Falcon lattice-based algorithm, specifically engineered for the parallel floating-point architecture of mobile GPUs (Qualcomm Adreno, ARM Mali, Apple GPU). The protocol decomposes Falcon's discrete Gaussian sampling into parallelizable wavelet segments that map directly to GPU shader pipelines, enabling full post-quantum identity generation on smartphones and IoT devices without cloud-based Hardware Security Modules (HSMs).

Key innovations:
- **The dual-trust-level execution model** is novel: no existing system provides graduated trust where an agent begins work under classical assurance and upgrades to post-quantum assurance asynchronously.
- **HTTP/2 multiplexed streaming of signature chunks** with per-chunk authentication is a novel transport mechanism for post-quantum cryptography.
- **GPU-shader-pipeline mapping for Falcon's discrete Gaussian sampler** is a novel approach to hardware acceleration of lattice-based cryptography.
- **The protocol enables post-quantum identity on devices with as little as 32KB of available memory**, down from 150KB+ required by standard ML-DSA implementations.

---

## 2. Problem Statement

### 2.1 SPHINCS+ Signatures Are Too Large for Single Transmission

SPHINCS+ (FIPS 205) is the only NIST-standardized stateless hash-based signature algorithm. Its security guarantees are exceptionally strong (relies only on hash function security), but its signatures are enormous:

| SPHINCS+ Parameter Set | Signature Size | Security Level |
|-----------------------|---------------|----------------|
| SPHINCS+-128s | 7,856 bytes | NIST Level 1 |
| SPHINCS+-128f | 17,088 bytes | NIST Level 1 |
| SPHINCS+-192s | 16,224 bytes | NIST Level 3 |
| SPHINCS+-192f | 35,664 bytes | NIST Level 3 |
| SPHINCS+-256s | 29,792 bytes | NIST Level 5 |
| SPHINCS+-256f | 49,856 bytes | NIST Level 5 |

A single SPHINCS+-256f signature (49,856 bytes) cannot fit in most HTTP header budgets and significantly impacts latency even in request bodies. For AI agents making hundreds of API calls per minute, transmitting 50KB of signature per request is prohibitive.

### 2.2 Edge Devices Cannot Run Standard PQ Algorithms

Post-quantum key generation and signing have substantial memory requirements:

| Algorithm | Peak Working Memory | Signing Time (ARM Cortex-A78) | Edge-Viable? |
|-----------|-------------------|-------------------------------|-------------|
| ML-DSA-44 | ~150KB | ~1.5ms | Marginal |
| ML-DSA-65 | ~200KB | ~2.5ms | Difficult |
| ML-DSA-87 | ~280KB | ~4.0ms | Very difficult |
| SPHINCS+-128s | ~40KB | ~80ms | Yes (but slow) |
| Falcon-512 | ~80KB (with FPU) | ~5ms | Requires FPU |
| Falcon-1024 | ~120KB (with FPU) | ~10ms | Requires FPU |

Edge AI agents running on IoT sensors, mobile devices, or embedded systems often have constrained memory (64-256KB available) and limited CPU capabilities. Standard ML-DSA implementations may not fit within the memory budget while the agent's primary ML model is loaded.

### 2.3 Latency-Sensitive Operations Cannot Wait for PQ Verification

SPHINCS+ verification (stateless parameter sets) takes 5-20ms depending on the parameter set. On edge devices, this can exceed 50ms. For latency-sensitive agent operations (real-time bidding, safety-critical actuator commands, streaming inference), waiting for full post-quantum verification before executing any action is unacceptable.

### 2.4 No Existing System Addresses These Constraints

| Approach | Handles Large Signatures | Edge-Optimized | Progressive Trust |
|----------|------------------------|---------------|-------------------|
| Standard SPHINCS+ | No (transmits full sig) | No | No |
| PAD-033 ZK Compression | Yes (for ML-DSA) | No (GPU prover) | No |
| XMSS (stateful) | Smaller sigs | No (state management) | No |
| WebCrypto API | No PQ support | Browser only | No |
| **This disclosure** | **Yes (chunked streaming)** | **Yes (GPU-accelerated)** | **Yes (dual-trust)** |

---

## 3. Solution: Variant A - Stateless Streaming Verification

### 3.1 Architecture Overview

```
Signing Agent                     Verifying Agent
    |                                    |
    |<-- 1. Classical sig (immediate) -->|
    |    (Ed25519, 64 bytes)             |
    |    Trust level: CLASSICAL          |
    |                                    |
    |    [Verifier begins LOW-RISK       |
    |     operations immediately]        |
    |                                    |
    |<-- 2. SPHINCS+ chunk 1/N --------->|
    |    (HTTP/2 stream, authenticated)  |
    |                                    |
    |<-- 3. SPHINCS+ chunk 2/N --------->|
    |    ...                             |
    |                                    |
    |<-- N. SPHINCS+ chunk N/N --------->|
    |                                    |
    |    [Verifier reconstructs +        |
    |     verifies full SPHINCS+]        |
    |                                    |
    |    Trust level: POST-QUANTUM       |
    |    [Verifier unlocks HIGH-RISK     |
    |     operations]                    |
```

### 3.2 Signature Chunking Protocol

The SPHINCS+ signature is divided into authenticated chunks for streaming:

```json
{
  "chunk_envelope": {
    "signature_id": "sphincs-2026-04-22-001",
    "total_chunks": 8,
    "chunk_index": 3,
    "chunk_data": "base64url_chunk_bytes",
    "chunk_hash": "sha256:H(chunk_data)",
    "running_merkle_root": "sha256:merkle_root_of_chunks_0_to_3",
    "chunk_auth": "ed25519_signature_over_chunk_envelope"
  }
}
```

**Chunking Strategy:**

| SPHINCS+ Parameter Set | Signature Size | Chunks (1KB each) | Streams Used |
|-----------------------|---------------|-------------------|-------------|
| SPHINCS+-128s | 7,856 bytes | 8 | 1 HTTP/2 stream |
| SPHINCS+-128f | 17,088 bytes | 17 | 2 HTTP/2 streams |
| SPHINCS+-192f | 35,664 bytes | 36 | 4 HTTP/2 streams |
| SPHINCS+-256f | 49,856 bytes | 50 | 5 HTTP/2 streams |

### 3.3 HTTP/2 Multiplexed Transport

Each chunk is transmitted as an independent HTTP/2 DATA frame on a dedicated stream:

```
HTTP/2 Connection
  |
  +-- Stream 1: Primary request/response (payload + classical sig)
  |     [Immediate, synchronous]
  |
  +-- Stream 3: SPHINCS+ chunks 1-10
  |     [Asynchronous, background]
  |
  +-- Stream 5: SPHINCS+ chunks 11-20
  |     [Asynchronous, background]
  |
  +-- Stream 7: SPHINCS+ chunks 21-30
        [Asynchronous, background]
```

**HTTP Trailing Headers Alternative:**

For HTTP/1.1 compatibility, SPHINCS+ chunks can be transmitted via HTTP trailing headers (RFC 7230 Section 4.1.2):

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked
X-Vouch-Classical-Sig: base64url_ed25519_64_bytes

[response body with payload]

X-Vouch-SPHINCS-Chunk-0: base64url_chunk_0
X-Vouch-SPHINCS-Chunk-1: base64url_chunk_1
...
X-Vouch-SPHINCS-Chunk-N: base64url_chunk_N
X-Vouch-SPHINCS-Merkle-Root: sha256_merkle_root
```

### 3.4 Dual-Trust-Level Execution Model

The verifier maintains a trust state machine for each active session:

```
UNSIGNED
  |
  [Classical signature verified]
  |
CLASSICAL_TRUST
  |
  [Agent may execute LOW-RISK operations]
  |  - Read-only queries
  |  - Non-financial transactions
  |  - Informational responses
  |  - Cached data access
  |
  [SPHINCS+ fully verified]
  |
POST_QUANTUM_TRUST
  |
  [Agent may execute ALL operations]
     - Financial transactions
     - Write operations
     - Credential issuance
     - Privileged API access
     - Safety-critical commands
```

**Trust Level Policy Configuration:**

```json
{
  "trust_policy": {
    "classical_trust_operations": [
      "api:read",
      "data:query",
      "status:check",
      "health:ping"
    ],
    "pq_trust_operations": [
      "api:write",
      "data:mutate",
      "payment:execute",
      "credential:issue",
      "actuator:command"
    ],
    "pq_verification_timeout_ms": 30000,
    "on_pq_timeout": "revoke_classical_trust",
    "on_pq_failure": "revoke_all_trust_and_rollback"
  }
}
```

### 3.5 Chunk Authentication and Integrity

Each chunk is individually authenticated to prevent injection or reordering:

```
Merkle Tree of Chunks:
          root
         /    \
      h01      h23
     /   \    /   \
   h0    h1  h2    h3
   |     |   |     |
  c_0   c_1  c_2   c_3

Each chunk envelope includes:
  - chunk_auth: Ed25519 signature over (signature_id || chunk_index || chunk_hash)
  - running_merkle_root: Merkle root of all chunks received so far

Verification:
  1. Verify chunk_auth (per-chunk integrity)
  2. After all chunks received, compute full Merkle root
  3. Compare against the root committed in the initial classical-signed header
  4. Reconstruct full SPHINCS+ signature from ordered chunks
  5. Verify SPHINCS+ signature over the original payload
```

This ensures:
- **No chunk injection:** Each chunk is Ed25519-signed; forged chunks are rejected.
- **No chunk reordering:** The Merkle tree enforces positional integrity.
- **Streaming verification:** The running Merkle root allows partial verification as chunks arrive, detecting tampering before all chunks are received.

### 3.6 Rollback on PQ Verification Failure

If SPHINCS+ verification fails after classical trust was already granted:

```
1. PQ verification FAILED
2. Revoke classical trust for this session
3. Identify all operations executed under classical trust
4. For reversible operations: execute rollback
5. For irreversible operations: flag for manual review
6. Log forensic event with full context
7. Increment agent's anomaly counter (PAD-016 behavioral monitoring)
```

---

## 4. Solution: Variant B - Ultra-Edge Falcon-Lite

### 4.1 The Falcon Memory Problem

Falcon (Fast Fourier Lattice-based Compact Signatures over NTRU) produces relatively compact signatures (666 bytes for Falcon-512) but requires a complex discrete Gaussian sampler during key generation and signing. The standard sampler uses:

- **Recursive FFT over floating-point numbers:** Requires 53-bit double-precision arithmetic.
- **Tree sampling with lazy interpolation:** Peak memory of approximately 80-120KB during signing.
- **Sequential processing:** The standard algorithm is inherently sequential, preventing parallelization.

Edge devices with 32-64KB of available memory and no hardware FPU cannot run standard Falcon.

### 4.2 GPU-Shader-Pipeline Decomposition

The key insight is that mobile GPUs (present in virtually all smartphones and many IoT devices) have massive floating-point throughput but are accessed through shader pipelines rather than traditional CPU instruction sets.

This disclosure decomposes Falcon's discrete Gaussian sampler into parallelizable wavelet segments that map to GPU compute shaders:

```
Standard Falcon Signing:
  1. Hash-to-point (SHAKE-256)        -> CPU (sequential, ~10us)
  2. FFT of target vector              -> GPU (parallel, ~50us)
  3. Gram-Schmidt decomposition        -> GPU (parallel, ~100us)
  4. Discrete Gaussian sampling        -> GPU (parallel, ~200us)
  5. Signature compression             -> CPU (sequential, ~20us)

GPU Shader Mapping:
  Step 2: 512/1024 butterfly operations -> 1 compute shader dispatch
          Each butterfly is independent -> maps to GPU work groups
  Step 3: Tree-level parallel reduction -> 1 compute shader dispatch
          Each tree level is independent -> maps to GPU work groups
  Step 4: Wavelet decomposition of sampler -> multiple compute dispatches
          Each coefficient sampling is semi-independent
          Rejection sampling parallelized across GPU threads
```

### 4.3 Memory-Constrained Falcon Variant

The Falcon-Lite variant reduces peak working memory by trading computation for memory:

**Standard Falcon-512 Memory Profile:**

| Data Structure | Size | Lifetime |
|---------------|------|----------|
| NTRU secret key (FFT form) | 8,192 bytes | Persistent |
| FFT working buffer | 16,384 bytes | Signing |
| Tree sampling buffer | 32,768 bytes | Signing |
| Gaussian sampler state | 16,384 bytes | Signing |
| Intermediate polynomials | 8,192 bytes | Signing |
| **Total peak** | **~82KB** | |

**Falcon-Lite Memory Profile (this disclosure):**

| Data Structure | Size | Technique |
|---------------|------|-----------|
| NTRU secret key (FFT form) | 8,192 bytes | Unchanged |
| FFT working buffer | 4,096 bytes | Streaming FFT (process 1/4 at a time) |
| Tree sampling buffer | 0 bytes | Offloaded to GPU shared memory |
| Gaussian sampler state | 0 bytes | Offloaded to GPU shared memory |
| GPU dispatch buffers | 2,048 bytes | Shader input/output staging |
| **Total peak (CPU)** | **~14KB** | |
| **GPU shared memory used** | **~48KB** | (Dedicated GPU memory, not CPU) |

The total CPU memory requirement drops from approximately 82KB to approximately 14KB, enabling Falcon signing on devices with as little as 32KB of available CPU memory, while the GPU's dedicated shared memory handles the computationally intensive tree sampling.

### 4.4 Composite Edge Signature

The Falcon-Lite signature is paired with a classical curve for hybrid security:

```json
{
  "edge_signature": {
    "algorithm": "secp256k1+falcon-lite-512",
    "classical": {
      "alg": "secp256k1",
      "signature": "base64url_64_bytes"
    },
    "pq": {
      "alg": "falcon-lite-512",
      "signature": "base64url_666_bytes",
      "gpu_accelerated": true,
      "device_attestation": {
        "gpu_model": "Adreno 750",
        "compute_shader_version": "OpenCL 3.0",
        "signing_time_ms": 8
      }
    },
    "total_size_bytes": 730
  }
}
```

**Size Comparison for Edge Agents:**

| Signature Scheme | Signature Size | Edge Memory Required | Edge Signing Time |
|-----------------|---------------|---------------------|-------------------|
| ML-DSA-44 (standard) | 2,420 bytes | ~150KB CPU | ~1.5ms CPU |
| Falcon-512 (standard) | 666 bytes | ~82KB CPU (needs FPU) | ~5ms CPU |
| Falcon-Lite-512 (this disclosure) | 666 bytes | ~14KB CPU + 48KB GPU | ~8ms GPU |
| Ed25519 (classical only) | 64 bytes | ~1KB | ~0.1ms |
| **secp256k1 + Falcon-Lite-512** | **730 bytes** | **~15KB CPU + 48KB GPU** | **~8ms total** |

### 4.5 GPU Compute Shader Specification

The Falcon-Lite discrete Gaussian sampler shader:

```
Shader: falcon_lite_gaussian_sampler
Input:  target_vector[512]     (fp64, from FFT output)
        gram_schmidt_basis[512] (fp64, from decomposition)
        random_seed[32]        (bytes, from secure RNG)
Output: gaussian_sample[512]   (int16, Falcon signature coefficients)

Workgroup size: 32 threads
Dispatches: 16 workgroups (512 coefficients / 32 threads)

Each thread:
  1. Load target coefficient and basis vector for assigned index
  2. Compute conditional mean and variance from basis
  3. Sample from discrete Gaussian using SampleZ algorithm
  4. Apply rejection sampling (probability < 2^-64)
  5. Write coefficient to output buffer

Memory per workgroup:
  - Shared: 3KB (basis coefficients for this workgroup)
  - Private: 64 bytes (thread-local sampler state)
  - Total shared across all workgroups: ~48KB
```

### 4.6 Device Attestation for GPU-Signed Content

Because GPU-accelerated signing involves non-standard execution environments, the protocol includes device attestation:

```json
{
  "device_attestation": {
    "gpu_model": "Adreno 750",
    "driver_version": "v685.0",
    "compute_capability": "OpenCL 3.0",
    "shader_hash": "sha256:H(falcon_lite_sampler_shader_source)",
    "constant_time_verified": true,
    "side_channel_mitigations": [
      "uniform_memory_access_pattern",
      "rejection_sampling_constant_iterations",
      "no_data_dependent_branching"
    ],
    "attestation_signature": "ed25519:device_manufacturer_signature"
  }
}
```

This attestation allows verifiers to assess whether the GPU-accelerated signing environment meets their security requirements.

---

## 5. Prior Art Differentiation

| System | Chunked PQ Signatures | Dual-Trust Execution | GPU-Accelerated PQ | Edge PQ (<32KB) |
|--------|---------------------|---------------------|-------------------|----------------|
| NIST PQC Standards | No | No | No | No |
| PQClean / liboqs | No | No | CPU reference only | No |
| PQCRYPTO project | No | No | Research GPU impl. | No |
| ARM PSA Crypto | No | No | No (CPU HAL) | ML-DSA subset |
| WebCrypto API | No PQ support | No | No | No |
| **This disclosure** | **Yes (HTTP/2 streams)** | **Yes (classical -> PQ)** | **Yes (shader pipeline)** | **Yes (14KB CPU)** |

Key differentiators:
1. **No existing system** provides progressive trust elevation where an agent operates under classical assurance while asynchronously streaming and verifying a post-quantum signature in the background.
2. **No existing system** transmits post-quantum signatures as authenticated, Merkle-tree-linked chunks over HTTP/2 multiplexed streams with per-chunk integrity guarantees.
3. **No existing system** decomposes Falcon's discrete Gaussian sampler into GPU compute shader workgroups, enabling post-quantum signing on mobile GPUs with approximately 14KB of CPU memory.
4. **No existing system** provides a dual-trust-level execution model with automatic rollback for operations performed under classical trust if post-quantum verification subsequently fails.
5. The combination of **stateless streaming verification + GPU-accelerated edge signing** creates a complete post-quantum deployment strategy for resource-constrained AI agents, covering both the transport problem (large signatures) and the compute problem (limited edge resources).

---

## 6. Technical Implementation

### 6.1 Data Model

```
Key: edge:agent:{did}:pq_config - Hash (variant, gpu_model, memory_budget_kb)
Key: edge:streaming:{sig_id}:chunks - List of chunk data (ordered)
Key: edge:streaming:{sig_id}:merkle - Merkle tree nodes
Key: edge:streaming:{sig_id}:status - Hash (chunks_received, chunks_expected, trust_level)
Key: edge:trust:{session_id} - Hash (trust_level, classical_verified_at, pq_verified_at, ops_executed)
Key: edge:rollback:{session_id} - List of reversible operations for potential rollback
```

### 6.2 Performance Targets

**Variant A (Streaming):**

| Metric | Target |
|--------|--------|
| Classical verification latency | < 1ms |
| Time to first chunk delivery | < 10ms |
| Full SPHINCS+-128s verification | < 200ms (8 chunks) |
| Full SPHINCS+-256f verification | < 2s (50 chunks) |
| Chunk authentication overhead | < 100 bytes per chunk |

**Variant B (Ultra-Edge):**

| Metric | Target |
|--------|--------|
| CPU memory for Falcon-Lite signing | <= 16KB |
| GPU shared memory for Falcon-Lite | <= 48KB |
| Signing time (mobile GPU) | <= 10ms |
| Verification time (CPU) | <= 2ms |
| Composite signature size | <= 800 bytes |

---

## 7. Claims Summary

The following aspects are disclosed as prior art:

1. A progressive post-quantum verification protocol where massive hash-based signatures (SPHINCS+) are sliced into authenticated, Merkle-tree-linked chunks transmitted over HTTP/2 multiplexed streams, with a lightweight classical signature providing immediate low-trust authorization while the post-quantum signature is asynchronously streamed and verified.

2. A dual-trust-level execution model where a verifying agent maintains a trust state machine that permits low-risk operations under classical signature assurance and gates high-risk operations behind full post-quantum signature verification, with automatic rollback if post-quantum verification fails.

3. A GPU-accelerated post-quantum signature scheme (Falcon-Lite) that decomposes the discrete Gaussian sampler into parallelizable wavelet segments mapped to GPU compute shader workgroups, reducing CPU memory requirements from approximately 82KB to approximately 14KB by offloading computationally intensive tree sampling to GPU shared memory.

4. A per-chunk authentication mechanism using Ed25519 signatures and running Merkle roots that enables streaming verification of signature chunks, detecting tampering before all chunks are received and preventing chunk injection, reordering, or omission attacks.

5. A device attestation protocol for GPU-accelerated cryptographic signing that includes shader source hashing, constant-time verification claims, and side-channel mitigation declarations, enabling verifiers to assess the security properties of the signing environment.

6. A composite edge signature format pairing a classical elliptic curve signature with a Falcon-Lite post-quantum signature, achieving hybrid cryptographic security in approximately 730 bytes with approximately 15KB of CPU memory, suitable for IoT sensors and mobile AI agents.

---

## Prior Art Declaration

This document is published as a defensive prior art disclosure under the Apache 2.0 license. The methods and systems described herein are hereby placed into the public domain to prevent patent monopolization. Any party implementing similar functionality after the publication date of this document cannot claim novelty for patent purposes.

**Reference Implementation:** https://github.com/vouch-protocol/vouch
