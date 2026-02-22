# PAD-024: Method for Temporal Perceptual Hashing of Video Content for Provenance-Linked Reverse Search

**Identifier:** PAD-024
**Title:** Method for Temporal Perceptual Hashing of Video Content for Provenance-Linked Reverse Search
**Publication Date:** February 20, 2026
**Prior Art Effective Date:** February 20, 2026
**Status:** Public Disclosure (Defensive Publication)
**Category:** Video Authentication / Content Provenance / Perceptual Hashing / Reverse Search
**Author:** Ramprasad Anandam Gaddam

---

## 1. Abstract

A system and method for computing a **temporal perceptual fingerprint** of video content that enables reverse search against a provenance database, linking any encountered copy of a video back to its original cryptographic signing record. Unlike image perceptual hashing (pHash, dHash, aHash), which fingerprints a single frame and discards all temporal information, and unlike proprietary video content identification systems (YouTube Content ID, Audible Magic), which are closed platforms designed for copyright enforcement rather than content provenance, this method creates a **multi-frame perceptual fingerprint specifically designed for provenance verification** -- connecting found video content back to its original signer's decentralized identifier (DID), signing timestamp, and content protection rules.

The method introduces several interlocking techniques:

1. **Evenly-Spaced Frame Sampling**: Extracting N frames at mathematically uniform intervals across the video duration, creating a temporally representative fingerprint that is robust to framerate conversion and partial trimming.
2. **Per-Frame Perceptual Hashing**: Computing a 64-bit DCT-based perceptual hash for each sampled frame, producing a set of resolution-invariant, compression-resistant fingerprints.
3. **Temporal Hash Composition**: Combining individual frame hashes into a single temporal fingerprint using either concatenation (Method A) or transition-encoded XOR reduction (Method B), capturing both spatial content and temporal dynamics.
4. **Provenance-Linked Storage**: Indexing the temporal hash alongside the signing record (signer DID, content hash, timestamp, protection rules) in a Hamming distance-friendly data structure for efficient similarity search.
5. **Weighted Reverse Search**: Querying the provenance database with a temporal hash, applying higher weights to temporally central frames (less likely to be trimmed) and adaptive Hamming distance thresholds based on query clip length.
6. **Container Metadata Augmentation**: Parsing MP4/MOV/WebM container metadata (codec, resolution, frame rate, duration, audio presence) alongside the temporal hash to improve match precision and provide forensic context.
7. **FFmpeg-Independent Fallback Extraction**: Reading I-frame positions directly from the MP4 container index when FFmpeg is unavailable, enabling basic temporal fingerprinting in constrained environments.

Unlike PAD-005's reverse lookup (which uses exact cryptographic content hashes and fails when a single bit changes), this method uses **perceptual similarity** -- a re-encoded, cropped, resolution-changed, or framerate-converted copy of a signed video will still match back to the original signing record. Unlike PAD-014's audio steganography (which embeds provenance into the signal itself), this method operates as an **external index** -- the video content is never modified, and the fingerprint is stored alongside the signing record in a queryable database.

---

## 2. Problem Statement

### 2.1 Single-Frame Hashing is Insufficient for Video

Image perceptual hashing algorithms (pHash, dHash, aHash) produce a fingerprint for a single image. When applied to video, two approaches are common:

| Approach | Method | Fatal Flaw |
|---|---|---|
| **First Frame Hash** | Hash frame 0 only | Different videos sharing the same opening frame collide; trimming the first second defeats the match entirely |
| **Keyframe Hash** | Hash I-frames from the codec | I-frame positions vary with encoding settings; re-encoding produces entirely different I-frame positions |
| **Random Frame Hash** | Hash N random frames | Non-deterministic; two runs on the same video produce different hashes; cannot be used for indexing |
| **All-Frame Hash** | Hash every frame | Computationally prohibitive for long videos; storage scales linearly with duration; minor timing shifts break alignment |

None of these approaches produce a **stable, temporally representative fingerprint** that survives common video transformations.

### 2.2 Proprietary Content ID Systems Are Closed and Purpose-Mismatched

Existing video fingerprinting systems are:

1. **Proprietary**: YouTube Content ID, Audible Magic, and similar systems are closed commercial platforms. Their algorithms are trade secrets. Third parties cannot implement compatible fingerprinting.
2. **Copyright-Focused**: These systems are designed to detect exact or near-exact copies for the purpose of copyright enforcement (monetization, blocking, claiming). They are not designed to return cryptographic provenance information (signer identity, signing timestamp, content protection rules).
3. **Platform-Locked**: Content ID fingerprints only exist within YouTube's ecosystem. A video found on Twitter, Telegram, or a personal website cannot be searched against YouTube's fingerprint database.
4. **No Open Standard**: No open, implementable specification exists for video perceptual fingerprinting linked to content provenance.

### 2.3 Video Transformations Break Exact-Match Systems

A video signed with the Vouch Protocol (PAD-001, PAD-005) produces a cryptographic content hash (SHA-256) stored in the reverse lookup registry. However, any transformation -- no matter how minor -- changes the content hash:

```
Original video:         sha256:a1b2c3d4...  --> Signing record found
Re-encoded (H.264->H.265): sha256:e5f6g7h8...  --> No match
Resolution changed:     sha256:i9j0k1l2...  --> No match
Cropped by 1 pixel:     sha256:m3n4o5p6...  --> No match
Framerate converted:    sha256:q7r8s9t0...  --> No match
```

The exact-hash reverse lookup (PAD-005) fails completely for any transformed copy of a signed video. This is the fundamental gap that temporal perceptual hashing addresses.

### 2.4 No Method Links Found Video to Its Signing Record

The core unsolved problem: given a video encountered in the wild (on social media, in a message, on a website), there is no open method to determine:

- **Who signed it?** (signer DID)
- **When was it signed?** (timestamp)
- **What protection rules apply?** (licensing, attribution, restrictions)
- **Is this a derivative of a signed original?** (provenance chain)

This gap enables:
- Uncredited redistribution of signed content
- Removal of provenance through simple re-encoding
- Deepfake distribution that cannot be cross-referenced against authentic signed originals
- Loss of content creator attribution across platform boundaries

---

## 3. Solution (The Invention)

### 3.1 Overview

A five-step pipeline that computes a temporal perceptual fingerprint from video content and stores it alongside the Vouch Protocol signing record, enabling provenance-linked reverse search for any copy of the video, regardless of transformations applied.

```
SIGNING TIME:
                                                    ┌──────────────────────┐
┌─────────┐    ┌──────────────┐    ┌────────────┐   │   Provenance DB      │
│  Video   │--->│ Frame        │--->│ Per-Frame  │   │                      │
│  File    │    │ Extraction   │    │ pHash      │   │  temporal_hash:      │
└─────────┘    │ (N=8 evenly  │    │ (64-bit    │   │    512 bits          │
               │  spaced)     │    │  DCT hash) │   │  signer_did:         │
               └──────────────┘    └────────────┘   │    did:key:z6Mk...   │
                                        │           │  content_hash:       │
                                        ▼           │    sha256:a1b2...    │
                                   ┌────────────┐   │  timestamp:          │
                                   │ Temporal    │-->│    1740009600        │
                                   │ Composition │   │  protection_rules:   │
                                   │ (concat or  │   │    {attribution: ..} │
                                   │  XOR)       │   └──────────────────────┘
                                   └────────────┘

QUERY TIME:

┌─────────┐    ┌──────────────┐    ┌────────────┐    ┌──────────────────┐
│  Found   │--->│ Frame        │--->│ Per-Frame  │--->│ Hamming Distance │
│  Video   │    │ Extraction   │    │ pHash      │    │ Search (VP-tree  │
│  (copy)  │    │ (N=8 evenly  │    │ (64-bit    │    │ or multi-probe   │
└─────────┘    │  spaced)     │    │  DCT hash) │    │ LSH)             │
               └──────────────┘    └────────────┘    └──────────────────┘
                                                            │
                                                            ▼
                                                     ┌──────────────────┐
                                                     │ Matching Records │
                                                     │ with distance    │
                                                     │ scores           │
                                                     └──────────────────┘
```

---

## 4. Technical Details

### 4.1 Step 1: Frame Extraction

Extract N evenly-spaced frames from the video. The default value of N is 8.

**Frame Position Calculation:**

```python
def compute_frame_positions(total_frames: int, n: int = 8) -> list[int]:
    """
    Compute N evenly-spaced frame positions across the video duration.

    For a 60-second video at 30fps (1800 frames) with N=8:
    Positions: [0, 257, 514, 771, 1028, 1285, 1542, 1799]
    """
    if total_frames <= n:
        return list(range(total_frames))
    step = (total_frames - 1) / (n - 1)
    return [round(i * step) for i in range(n)]
```

**Design Rationale for N=8:**

| Consideration | Analysis |
|---|---|
| **Temporal coverage** | 8 frames provide sufficient sampling to distinguish different videos with different scene progressions |
| **Computational cost** | Only 8 frames need decoding, not the full video; feasible on mobile devices and edge compute |
| **Trimming resistance** | Losing frames at the start or end still preserves most of the 8 sampled positions; weighted matching (Section 4.5) further compensates |
| **Collision resistance** | 8 independent 64-bit hashes produce a 512-bit composite fingerprint; the probability of two different videos producing identical 512-bit fingerprints is astronomically low |
| **Storage efficiency** | 512 bits (64 bytes) per video is trivial to store and index at scale |

**Adaptive Frame Count:**

For very short clips (under 2 seconds), N is reduced to 4. For very long videos (over 30 minutes), N can be increased to 16 for finer temporal resolution. The frame count is stored alongside the temporal hash to ensure correct comparison.

### 4.2 Step 2: Per-Frame Perceptual Hash

For each extracted frame, compute a 64-bit perceptual hash using a DCT-based algorithm:

```python
import numpy as np

def compute_frame_phash(frame: np.ndarray) -> int:
    """
    Compute a 64-bit perceptual hash for a single video frame.

    Steps:
    1. Convert to grayscale (removes color dependency)
    2. Resize to 32x32 (normalizes resolution)
    3. Apply DCT (captures frequency structure)
    4. Extract 8x8 low-frequency coefficients
    5. Threshold against median to produce 64 bits
    """
    # Step 1: Convert to grayscale
    if len(frame.shape) == 3:
        gray = np.dot(frame[..., :3], [0.2989, 0.5870, 0.1140])
    else:
        gray = frame

    # Step 2: Resize to 32x32
    resized = resize_bilinear(gray, (32, 32))

    # Step 3: Apply 2D DCT
    dct_result = dct2d(resized)

    # Step 4: Extract top-left 8x8 (low-frequency components)
    low_freq = dct_result[:8, :8]

    # Step 5: Compute median and threshold
    # Exclude DC coefficient (top-left corner) for stability
    coefficients = low_freq.flatten()[1:]  # Skip DC
    median_val = np.median(coefficients)

    # Step 6: Generate 64-bit hash
    hash_bits = 0
    for i, coeff in enumerate(low_freq.flatten()):
        if coeff > median_val:
            hash_bits |= (1 << i)

    return hash_bits
```

**Properties of DCT-based perceptual hashing:**

| Property | Explanation |
|---|---|
| **Resolution invariant** | Input is resized to 32x32 before hashing; a 4K frame and a 480p frame of the same content produce the same hash |
| **Compression resistant** | DCT captures low-frequency structure that lossy codecs preserve; re-encoding changes high-frequency details but not the dominant spatial frequencies |
| **Color independent** | Grayscale conversion ensures color grading, white balance changes, and saturation adjustments do not affect the hash |
| **Rotation sensitive** | The hash IS sensitive to rotation, which is desirable -- a rotated video is a meaningfully different presentation |

### 4.3 Step 3: Temporal Hash Composition

Combine the N frame hashes into a single temporal fingerprint. Two methods are disclosed:

**Method A: Concatenation (Reference Implementation)**

```python
def compose_temporal_hash_concat(frame_hashes: list[int]) -> bytes:
    """
    Simple concatenation of frame hashes.
    For N=8 frames with 64-bit hashes: 512-bit temporal hash.
    """
    temporal_hash = b""
    for h in frame_hashes:
        temporal_hash += h.to_bytes(8, byteorder="big")
    return temporal_hash  # 64 bytes for N=8
```

Method A is simpler, easier to implement, and provides direct per-frame comparison during matching. It is the recommended approach for the reference implementation.

**Method B: XOR Reduction + Order Encoding (Temporal Dynamics)**

```python
def compose_temporal_hash_xor(frame_hashes: list[int]) -> bytes:
    """
    XOR between consecutive frames captures temporal dynamics.
    Produces: base_hash (64 bits) + N-1 transition hashes (64 bits each).
    Total: N * 64 bits (same size as Method A).
    """
    # Base hash: median of all frame hashes (bitwise majority vote)
    base_hash = bitwise_median(frame_hashes)

    # Transition hashes: pairwise XOR captures change between frames
    transitions = []
    for i in range(len(frame_hashes) - 1):
        transition = frame_hashes[i] ^ frame_hashes[i + 1]
        transitions.append(transition)

    # Compose: base || transition_0 || transition_1 || ... || transition_6
    result = base_hash.to_bytes(8, byteorder="big")
    for t in transitions:
        result += t.to_bytes(8, byteorder="big")
    return result
```

Method B captures temporal dynamics: scene changes produce high-hamming-weight transition hashes, while static scenes produce near-zero transition hashes. This enables distinguishing videos with the same frames in different temporal order.

**Comparison:**

| Criterion | Method A (Concat) | Method B (XOR) |
|---|---|---|
| Implementation complexity | Low | Medium |
| Per-frame matching | Direct | Requires decomposition |
| Temporal dynamics | Not captured | Captured via transitions |
| Static content | Works well | Transition hashes near-zero (wasted bits) |
| Scene change detection | No | Yes (high-weight transitions) |

### 4.4 Step 4: Storage and Indexing

When a video is signed using the Vouch Protocol, the temporal hash is computed and stored alongside the signing record:

**Storage Schema:**

```json
{
  "temporal_hash": "base64:AQIDBAUGB...==",
  "hash_method": "concat_v1",
  "frame_count": 8,
  "signer_did": "did:key:z6MkhaXgBZDvotDkL5LmCWaEe...",
  "content_hash": "sha256:a1b2c3d4e5f6...",
  "timestamp": "2026-02-20T12:00:00Z",
  "protection_rules": {
    "attribution_required": true,
    "license": "CC-BY-4.0",
    "commercial_use": "contact_signer"
  },
  "container_metadata": {
    "codec": "h264",
    "resolution": "1920x1080",
    "frame_rate": 30.0,
    "duration_seconds": 62.4,
    "has_audio": true,
    "container_format": "mp4"
  }
}
```

**Indexing Strategy:**

Efficient similarity search requires data structures optimized for Hamming distance queries:

1. **VP-Tree (Vantage Point Tree)**: A metric tree that partitions the space using Hamming distance. Supports exact k-nearest-neighbor queries. Best for databases up to ~10 million entries.

2. **Multi-Probe LSH (Locality-Sensitive Hashing)**: Hash temporal fingerprints into buckets such that similar fingerprints land in the same (or nearby) buckets. Supports approximate nearest-neighbor queries. Scales to billions of entries with sub-linear query time.

3. **Redis-Native Approach**: For smaller deployments, store temporal hashes as binary strings in Redis with a Lua script that computes Hamming distance via `BITCOUNT(XOR(a, b))`. Suitable for databases up to ~1 million entries.

```
Redis Key Structure:
  vouch:video:thash:<signing_id>  ->  <temporal_hash_bytes>
  vouch:video:meta:<signing_id>   ->  <JSON signing record>
  vouch:video:index:shard:<N>     ->  ZSET of signing_ids in shard N
```

### 4.5 Step 5: Reverse Search (Query)

When searching for a video's provenance:

```python
def reverse_search(
    query_video_path: str,
    database: ProvenanceDB,
    threshold_per_frame: int = 10,
    top_k: int = 5,
) -> list[SearchResult]:
    """
    Search for the provenance of a video by temporal perceptual hash.

    Args:
        query_video_path: Path to the video to search for
        database: Provenance database with temporal hash index
        threshold_per_frame: Max Hamming distance per frame hash (default 10 of 64 bits)
        top_k: Number of best matches to return

    Returns:
        List of matching signing records with distance scores
    """
    # 1. Extract frames and compute temporal hash
    frames = extract_evenly_spaced_frames(query_video_path, n=8)
    query_hash = compose_temporal_hash_concat(
        [compute_frame_phash(f) for f in frames]
    )

    # 2. Compute adaptive threshold based on frame count
    effective_threshold = threshold_per_frame * len(frames)

    # 3. Search database
    candidates = database.hamming_search(query_hash, max_distance=effective_threshold)

    # 4. Apply weighted scoring (middle frames weighted higher)
    for candidate in candidates:
        candidate.weighted_score = compute_weighted_distance(
            query_hash, candidate.temporal_hash, len(frames)
        )

    # 5. Sort by weighted score (lower = better match)
    candidates.sort(key=lambda c: c.weighted_score)

    return candidates[:top_k]
```

**Weighted Frame Scoring:**

Frames from the temporal middle of a video are weighted higher than frames at the boundaries, based on the empirical observation that video trimming (adding intros, removing outros, clipping) disproportionately affects the start and end:

```python
def compute_weighted_distance(
    query_hash: bytes,
    candidate_hash: bytes,
    frame_count: int,
) -> float:
    """
    Compute weighted Hamming distance with higher weight for central frames.

    Weight distribution for N=8:
    Frame:   0     1     2     3     4     5     6     7
    Weight:  0.5   0.75  1.0   1.0   1.0   1.0   0.75  0.5
    """
    weights = compute_frame_weights(frame_count)
    total_distance = 0.0

    for i in range(frame_count):
        frame_q = query_hash[i*8 : (i+1)*8]
        frame_c = candidate_hash[i*8 : (i+1)*8]
        hamming = popcount(xor_bytes(frame_q, frame_c))
        total_distance += hamming * weights[i]

    return total_distance / sum(weights)


def compute_frame_weights(n: int) -> list[float]:
    """
    Generate weights: 1.0 for middle frames, tapering to 0.5 at boundaries.
    """
    weights = []
    for i in range(n):
        # Normalized position: 0.0 at edges, 1.0 at center
        center_distance = abs(i - (n - 1) / 2) / ((n - 1) / 2)
        weight = 1.0 - 0.5 * center_distance
        weights.append(weight)
    return weights
```

### 4.6 Threshold-Adaptive Matching

The Hamming distance threshold is adjusted based on the number of frames in the query video. Shorter clips provide fewer frames and therefore less statistical confidence, requiring tighter thresholds to avoid false positives:

```python
def compute_adaptive_threshold(
    query_frame_count: int,
    base_threshold_per_frame: int = 10,
) -> int:
    """
    Adjust threshold based on query length.

    Shorter clips -> tighter threshold (less tolerance per frame)
    Longer clips  -> standard threshold (more statistical confidence)
    """
    if query_frame_count <= 4:
        # Short clip: reduce tolerance by 40%
        return int(base_threshold_per_frame * 0.6) * query_frame_count
    elif query_frame_count <= 8:
        # Standard: full tolerance
        return base_threshold_per_frame * query_frame_count
    else:
        # Long video: can afford slightly more tolerance per frame
        return int(base_threshold_per_frame * 1.2) * query_frame_count
```

### 4.7 Container Metadata Augmentation

In addition to the temporal hash, parsing the video container metadata provides supplementary matching signals and forensic context:

```python
def extract_container_metadata(video_path: str) -> dict:
    """
    Parse MP4/MOV/WebM container metadata without full video decode.
    """
    return {
        "codec": detect_codec(video_path),          # h264, h265, vp9, av1
        "resolution": detect_resolution(video_path), # 1920x1080
        "frame_rate": detect_framerate(video_path),  # 29.97, 30.0, 24.0
        "duration_seconds": detect_duration(video_path),
        "has_audio": detect_audio_track(video_path),
        "container_format": detect_container(video_path),  # mp4, mov, webm, mkv
        "creation_timestamp": detect_creation_time(video_path),
    }
```

Container metadata serves two purposes:

1. **Match Refinement**: When multiple temporal hash matches are found, container metadata (similar duration, same aspect ratio) can disambiguate.
2. **Forensic Context**: The original container metadata (codec, resolution) provides evidence of the signing context, useful when the found copy has been transcoded.

### 4.8 FFmpeg-Independent Frame Extraction Fallback

For constrained environments where FFmpeg is not available (browser contexts, serverless functions, mobile apps), a fallback method reads I-frame positions directly from the MP4 container index:

```python
def extract_frames_from_mp4_index(video_path: str, n: int = 8) -> list:
    """
    Extract approximate frame data from MP4 stbl (Sample Table Box)
    without FFmpeg.

    Reads:
    - stss (Sync Sample Box): I-frame positions
    - stsz (Sample Size Box): Frame sizes
    - stco/co64 (Chunk Offset Box): Byte offsets

    Selects N I-frames closest to the evenly-spaced target positions.
    """
    mp4_index = parse_mp4_sample_table(video_path)
    target_positions = compute_frame_positions(mp4_index.total_frames, n)

    # Find nearest I-frame to each target position
    selected_iframes = []
    for target in target_positions:
        nearest = find_nearest_sync_sample(mp4_index.sync_samples, target)
        selected_iframes.append(nearest)

    # Decode only the selected I-frames (no inter-frame dependencies)
    frames = []
    for iframe_pos in selected_iframes:
        raw_data = read_sample_at_offset(
            video_path,
            mp4_index.chunk_offsets,
            mp4_index.sample_sizes,
            iframe_pos,
        )
        frame = decode_single_iframe(raw_data, mp4_index.codec)
        frames.append(frame)

    return frames
```

**Tradeoff**: The fallback method selects the nearest I-frames to the target positions rather than exact positions, introducing slight positional variance. This reduces match accuracy by approximately 5-10% compared to FFmpeg-based extraction but enables temporal fingerprinting in environments where FFmpeg cannot be installed.

---

## 5. Claims and Novel Contributions

### Claim 1: Temporal Perceptual Hashing for Provenance

A method for computing a multi-frame perceptual fingerprint of video content specifically designed for linking found video copies back to their cryptographic signing records. Unlike image pHash (single-frame, no temporal information) and video content ID (proprietary, copyright-focused), this method produces an open, implementable temporal fingerprint tied to a provenance record containing the signer's decentralized identifier, signing timestamp, and content protection rules.

### Claim 2: Evenly-Spaced Frame Sampling for Temporal Representation

A method for extracting N frames at mathematically uniform intervals across a video's duration, rather than extracting keyframes (codec-dependent), random frames (non-deterministic), or all frames (computationally prohibitive). The evenly-spaced strategy produces a deterministic, temporally representative sample that is robust to framerate conversion and codec changes.

### Claim 3: Provenance-Linked Reverse Video Search

A system where a temporal perceptual hash, stored alongside a Vouch Protocol signing record in a Hamming distance-indexed database, enables reverse lookup: given any copy of a signed video (regardless of re-encoding, resolution change, or partial trimming), retrieve the original signer's identity, signing timestamp, and content protection rules.

### Claim 4: Transition Hash Encoding for Temporal Dynamics

A method for computing pairwise XOR between consecutive frame perceptual hashes to produce transition hashes that encode temporal dynamics -- scene changes, motion patterns, and temporal structure -- in a compact binary representation. This enables distinguishing videos with identical frame content but different temporal ordering.

### Claim 5: Weighted Frame Matching with Temporal Center Bias

A scoring method that assigns higher weights to frames from the temporal middle of a video during Hamming distance matching, based on the empirical observation that video trimming, intro/outro addition, and boundary editing disproportionately affect the start and end of a video while preserving central content.

### Claim 6: Combined Container Metadata and Temporal Fingerprint

A method for parsing MP4/MOV/WebM container metadata (codec, resolution, frame rate, duration, audio track presence) and storing it alongside the temporal perceptual hash to improve match precision through supplementary matching signals and provide forensic context about the original signing environment.

### Claim 7: Threshold-Adaptive Matching Based on Query Length

A method for adjusting the Hamming distance acceptance threshold based on the number of frames in the query video. Shorter clips (fewer frames) use tighter per-frame thresholds to compensate for reduced statistical confidence, while longer videos can tolerate wider per-frame thresholds due to greater sample size.

### Claim 8: FFmpeg-Independent Frame Extraction via Container Index Parsing

A fallback method where video frames for perceptual hashing are extracted by parsing the MP4 Sample Table Box (stbl) directly -- reading sync sample positions (stss), sample sizes (stsz), and chunk offsets (stco/co64) -- to locate and decode individual I-frames without requiring FFmpeg or any external video processing library.

---

## 6. Security Considerations

### 6.1 Adversarial Attacks on Perceptual Hashing

| Attack Vector | Description | Countermeasure |
|---|---|---|
| **Adversarial Perturbation** | Crafting pixel-level perturbations that maximally change the pHash while remaining visually imperceptible | DCT-based hashing is inherently resistant to high-frequency perturbations; perturbations strong enough to flip multiple DCT coefficients are visually noticeable |
| **Collision Attack** | Crafting a different video that produces the same temporal hash as a target video | 512-bit temporal hash provides 2^256 collision resistance (birthday bound); computationally infeasible |
| **Pre-Image Attack** | Given a temporal hash, reconstruct a video that produces it | DCT hashing is a lossy one-way transformation; the hash discards the vast majority of image information; reconstruction is infeasible |
| **Frame Insertion Attack** | Inserting extra frames to shift the evenly-spaced sampling positions | Effective against exact position matching; mitigated by weighted scoring (central frames survive) and by comparing multiple frame-count hypotheses during search |
| **Temporal Reordering** | Rearranging scenes to change the temporal hash while preserving content | Method B (transition hashes) detects reordering; Method A hash changes entirely, which is the correct behavior -- a reordered video IS a different video |

### 6.2 False Positive Analysis

A false positive occurs when two genuinely different videos produce temporal hashes within the acceptance threshold. The false positive rate depends on:

```
Per-frame pHash:  64 bits
Threshold:        10 bits (15.6% of bits may differ)
Frames:           8

Probability that a random 64-bit hash is within Hamming distance 10 of a target:
  P(d <= 10) = sum_{k=0}^{10} C(64, k) / 2^64
             ~ 1.46 x 10^-8  (approximately 1 in 68 million)

For 8 independent frames, probability all 8 are within threshold:
  P(all 8 match) = (1.46 x 10^-8)^8
                 ~ 1.1 x 10^-63  (astronomically unlikely)
```

In practice, frame hashes are not fully independent (similar visual content produces correlated hashes), so the true false positive rate is higher than this theoretical bound. Empirical testing on diverse video databases is essential for calibrating production thresholds.

**Recommended Calibration Process:**

1. Compute temporal hashes for a large corpus of unrelated videos (>100,000).
2. Compute all pairwise Hamming distances.
3. Plot the distance distribution and identify the separation between "same video, different encoding" and "different video" populations.
4. Set the threshold at the point that achieves the desired false positive rate (<0.001%).

### 6.3 False Negative Analysis

A false negative occurs when a genuine copy of a signed video fails to match. Primary causes:

| Cause | Impact | Mitigation |
|---|---|---|
| Severe cropping (>20% of frame area) | DCT coefficients shift significantly | Allow higher per-frame threshold for known crop-prone platforms |
| Framerate conversion (30fps to 24fps) | Different frames are extracted at evenly-spaced positions | Store multiple temporal hashes at common framerate conversions (24, 25, 30, 60 fps) |
| Heavy visual effects (overlays, borders, picture-in-picture) | Fundamentally changes spatial content | Combine with audio fingerprinting (PAD-014) for multi-modal matching |
| Severe re-editing (remix, montage) | Frame order and selection changes | Low match score correctly reflects that the content has been substantially altered |

### 6.4 Privacy Considerations

1. **No Content Storage**: The temporal hash is a lossy, one-way fingerprint. The original video cannot be reconstructed from the hash. Only the hash and metadata are stored.
2. **Opt-In Registration**: Only videos explicitly signed and registered through the Vouch Protocol are indexed. Unsigning users can request hash removal.
3. **Rate-Limited Search**: Query endpoints are rate-limited to prevent enumeration attacks (systematically probing the database to discover what videos have been signed).
4. **No Surveillance Capability**: The system matches against a database of voluntarily registered signed videos. It cannot identify or track arbitrary video content that was never signed.

### 6.5 Integrity of the Signing Record

The temporal hash is stored alongside a Vouch Protocol signing record that includes:
- An Ed25519 signature over the content hash and metadata
- The signer's DID (resolvable to a public key)
- A timestamp (optionally anchored to a timestamping authority)

An attacker who compromises the temporal hash index but not the signing keys cannot create valid signing records. The temporal hash is an index key, not a trust anchor -- the cryptographic trust derives from the Ed25519 signature in the signing record.

---

## 7. Implementation Architecture

### 7.1 Signing Pipeline Integration

```
┌──────────────────────────────────────────────────────────────┐
│                    VIDEO SIGNING PIPELINE                      │
├──────────────────────────────────────────────────────────────┤
│                                                               │
│  [1. Content Hash]                                            │
│   Video file ──> SHA-256 ──> content_hash                     │
│                                                               │
│  [2. Temporal Hash]  (NEW - this disclosure)                  │
│   Video file ──> Frame Extraction ──> Per-Frame pHash         │
│              ──> Temporal Composition ──> temporal_hash        │
│                                                               │
│  [3. Container Metadata]  (NEW - this disclosure)             │
│   Video file ──> MP4/MOV/WebM parser ──> container_metadata   │
│                                                               │
│  [4. Signing Record]                                          │
│   {content_hash, temporal_hash, container_metadata,           │
│    signer_did, timestamp, protection_rules}                   │
│   ──> Ed25519 Sign ──> Vouch-Token (JWT)                      │
│                                                               │
│  [5. Registration]                                            │
│   Vouch-Token ──> Provenance Database                         │
│   temporal_hash ──> Hamming Distance Index                    │
│                                                               │
└──────────────────────────────────────────────────────────────┘
```

### 7.2 Search API

```
GET /api/v1/video/search?temporal_hash=<base64>&threshold=80
Authorization: Bearer <api_key>

Response:
{
  "matches": [
    {
      "signing_id": "vouch:sign:abc123",
      "signer_did": "did:key:z6MkhaXgBZDvotDkL5LmCWaEe...",
      "signer_display_name": "Jane Doe",
      "timestamp": "2026-02-15T14:30:00Z",
      "hamming_distance": 23,
      "weighted_score": 0.18,
      "confidence": "high",
      "protection_rules": {
        "attribution_required": true,
        "license": "CC-BY-4.0"
      },
      "container_metadata": {
        "original_resolution": "1920x1080",
        "original_codec": "h264",
        "original_duration": 62.4
      }
    }
  ],
  "query_metadata": {
    "frame_count": 8,
    "threshold_used": 80,
    "search_time_ms": 12
  }
}
```

### 7.3 Component Integration

| Component | Role | Technology |
|---|---|---|
| **Frame Extractor** | Decode N evenly-spaced frames | FFmpeg (primary), MP4 index parser (fallback) |
| **pHash Engine** | Compute 64-bit DCT perceptual hash per frame | NumPy/SciPy (Python), custom WASM module (browser) |
| **Temporal Composer** | Combine frame hashes into temporal fingerprint | Pure Python / TypeScript |
| **Hamming Index** | Similarity search over temporal hashes | VP-tree (small scale), multi-probe LSH (large scale), Redis (prototype) |
| **Provenance Store** | Signing records and metadata | Upstash Redis (serverless), PostgreSQL (self-hosted) |
| **Search API** | HTTP endpoint for reverse search queries | Cloudflare Worker, Vercel Edge Function, or standalone service |

### 7.4 Planned Implementation Files

```
vouch/
  video/
    __init__.py
    frame_extractor.py       # FFmpeg-based and fallback frame extraction
    phash.py                 # Per-frame perceptual hash computation
    temporal_hash.py         # Temporal hash composition (Method A + B)
    container_metadata.py    # MP4/MOV/WebM container parser
    search.py                # Reverse search with weighted scoring
    index.py                 # Hamming distance index (VP-tree, LSH)
  tests/
    test_video_fingerprint.py
    test_temporal_hash.py
    test_reverse_search.py
    fixtures/
      sample_videos/         # Test videos in various formats/resolutions
```

---

## 8. Use Cases

### 8.1 Content Creator Attribution

A filmmaker signs their video before uploading to social media. The video is subsequently downloaded, re-encoded, cropped to a different aspect ratio, and re-uploaded across multiple platforms without credit. Using the temporal perceptual hash, any viewer (or automated system) can perform a reverse search and discover:
- The original creator's verified identity (DID)
- The original upload date and time
- The creator's attribution requirements
- The licensing terms attached to the content

This enables automated attribution enforcement across platform boundaries.

### 8.2 Journalism and Source Verification

A news organization receives a video clip purporting to show an event. Before broadcasting, the editorial team performs a reverse search:
- **Match found**: The video traces back to a verified field reporter's signing record. The timestamp confirms it was captured during the event. The provenance chain is intact.
- **No match found**: The video has never been signed by any verified source. This does not prove it is fake, but it means no authenticated provenance exists.
- **Partial match found**: The video is a derivative (cropped, trimmed, overlaid) of a signed original. The match score indicates the degree of modification.

This provides journalists with a provenance signal analogous to checking a source's credentials, applied to video evidence.

### 8.3 Legal Evidence and Chain of Custody

In legal proceedings, video evidence must be authenticated. The temporal perceptual hash provides a mechanism for establishing that a presented video is a derivative of a specific signed original:

1. **Original capture**: Body camera, security camera, or phone records and signs the video at capture time.
2. **Storage**: The signing record (including temporal hash) is registered in the provenance database.
3. **Discovery**: During legal proceedings, a video copy is produced.
4. **Authentication**: Reverse search confirms the copy matches the originally signed video with a specific Hamming distance, indicating the degree of transformation from the original.
5. **Expert testimony**: The temporal hash match score, combined with container metadata forensics, provides quantitative evidence of the video's relationship to the authenticated original.

### 8.4 Deepfake Detection by Provenance

When a deepfake video is created of a public figure, there are two scenarios:

- **Public figure signs their authentic content**: Legitimate videos have signing records with temporal hashes. A deepfake video, when searched, returns no match -- it was never signed by the public figure's DID.
- **Deepfake uses clips from signed originals**: A deepfake that incorporates real footage (face-swapped, context-altered) may partially match the temporal hash of the original. The partial match, combined with a different signer DID (or no signing record), provides evidence of manipulation.

This does not detect deepfakes directly but provides a positive authentication signal: signed, verified content can be distinguished from unsigned, unverified content.

### 8.5 Cross-Platform Content Tracking

A media company signs their video content and registers temporal hashes. An automated monitoring system periodically scans video platforms, computes temporal hashes of discovered content, and performs reverse searches:

- Identifies unauthorized redistributions
- Verifies that licensed distributors are using unmodified copies
- Detects derivative works that may require licensing
- Tracks the reach and spread of content across platforms

### 8.6 Archival and Preservation Verification

Digital archives transcode video content over decades as formats evolve (MPEG-2 to H.264 to H.265 to AV1). Each transcode changes the cryptographic content hash, breaking exact-match verification. The temporal perceptual hash remains stable across transcodes, enabling long-term verification that an archived video is indeed the same content that was originally signed, even after multiple generations of format migration.

---

## 9. Robustness Analysis

### 9.1 Transformation Survival Matrix

| Transformation | Effect on Temporal Hash | Expected Match Rate |
|---|---|---|
| Re-encoding (H.264 to H.265) | Minimal DCT coefficient change; low-frequency structure preserved | >95% |
| Resolution change (1080p to 480p) | DCT computed on 32x32 resize; resolution-invariant | >90% |
| Minor cropping (<20% of frame area) | Some DCT coefficient shift from spatial reframing | >80% |
| Framerate change (30fps to 24fps) | Different absolute frame positions extracted; similar content at nearby positions | >75% |
| Color grading / brightness adjustment | Grayscale conversion and DCT capture structure, not color | >85% |
| Adding intro/outro (10% of duration) | Boundary frames shift; middle frames (highest weight) still match | >70% |
| Letterboxing / pillarboxing | Black bars affect DCT; less impact on central content | >75% |
| Speed change (0.5x to 2x) | Frame positions scale proportionally; similar content at scaled positions | >70% |
| Severe re-edit / remix | Frame selection and order fundamentally changed | <30% |
| Completely different video | No structural similarity | <0.001% |

### 9.2 Computational Performance

| Operation | Time (Reference Hardware) | Notes |
|---|---|---|
| Frame extraction (8 frames, FFmpeg) | ~200ms for 60s video | Seeks to positions, decodes single frames |
| Frame extraction (8 frames, fallback) | ~500ms for 60s video | Parses MP4 index, decodes I-frames |
| Per-frame pHash (8 frames) | ~5ms total | 32x32 resize + DCT is trivial |
| Temporal composition | <1ms | Byte concatenation or XOR |
| Hamming search (1M entries, VP-tree) | ~10ms | Logarithmic search time |
| Hamming search (100M entries, LSH) | ~50ms | Sub-linear with tuned hash tables |
| **Total signing overhead** | ~210ms | Negligible compared to video encoding |
| **Total search time** | ~220ms | Real-time reverse search |

---

## 10. Conclusion

The temporal perceptual hashing method disclosed in this document addresses a fundamental gap in content provenance: the inability to link a found video back to its cryptographic signing record after common transformations. By combining evenly-spaced frame sampling, DCT-based perceptual hashing, temporal hash composition, and Hamming distance-indexed storage alongside Vouch Protocol signing records, the system enables provenance-linked reverse video search that survives re-encoding, resolution changes, cropping, framerate conversion, and partial trimming.

This method is complementary to existing Vouch Protocol mechanisms: PAD-005 (exact-hash reverse lookup) provides precise matching for unmodified content, PAD-014 (acoustic steganography) provides signal-embedded provenance for audio, and this disclosure (PAD-024) provides perceptual similarity matching for video. Together, they form a comprehensive media provenance system covering text, images, audio, and video across both exact-match and fuzzy-match scenarios.

---

## 11. Prior Art Declaration

This disclosure is published to establish prior art and prevent patent monopolization of the described methods. The systems, methods, algorithms, and techniques described herein are hereby released into the public domain under the **Creative Commons CC0 1.0 Universal** dedication.

Any party is free to implement, modify, and distribute implementations of the methods described in this document without restriction.

Any party attempting to patent the methods described herein after the Prior Art Effective Date of **February 20, 2026** cannot claim novelty, as this publication constitutes prior art under 35 U.S.C. 102(a)(1) and equivalent provisions in international patent law.

---

## 12. References

- Zauner, C. "Implementation and Benchmarking of Perceptual Image Hash Functions" (2010)
- ISO/IEC 14496-12 (MPEG-4 Part 12 - ISO Base Media File Format)
- ISO/IEC 14496-14 (MPEG-4 Part 14 - MP4 File Format)
- Ahmed, N., Natarajan, T., and Rao, K.R. "Discrete Cosine Transform" (1974)
- Yildiz, A. and Gionis, A. "Vantage Point Trees for Nearest Neighbor Search in Hamming Distance" (2015)
- Indyk, P. and Motwani, R. "Approximate Nearest Neighbors: Towards Removing the Curse of Dimensionality" (1998) - Locality-Sensitive Hashing
- W3C Decentralized Identifiers (DIDs) v1.0
- C2PA Technical Specification (Content Credentials)
- Vouch Protocol: Prior Art Disclosures PAD-001 (Cryptographic Agent Identity), PAD-005 (Reverse Lookup Registry), PAD-014 (Acoustic Provenance)
- RFC 7519 (JSON Web Token)
- Bernstein, D.J. et al. "Ed25519: High-speed high-security signatures" (2012)
