"""
Per-region authorship attribution for mixed human and AI code.

When an AI coding assistant and a human both edit a file, git blame credits
every line to the human who committed it. The AI's work is laundered through
the human's identity, so when a line later causes an incident nobody can prove
whether a human or a machine wrote it.

This module records authorship at the moment of editing, from the actual edit
channel, and signs each party's regions with that party's own key:

  * Lines produced by the AI assistant are captured as the assistant makes
    them (its Edit / Write operations) and attested with an AI-session key that
    the human's editor does not wield.
  * Lines the human typed are the residual: anything that changed on disk that
    did not arrive through the assistant's edit channel.
  * Lines untouched since the session began are marked preexisting.

The result is a signed Attribution Manifest that binds, per file, exact line
ranges to an author DID, over the exact bytes, with a JCS Data Integrity proof.
A region cannot be moved, the bytes cannot be altered, and an AI region cannot
be invented without the AI-session signature.

Legitimacy, not labelling. The naive version (one party stamps both keys) is
worthless because the stamper controls both. The value here comes from two
properties this module enforces: capture from the real edit channel, and an
AI-session key held apart from the human signer.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from . import data_integrity
from .keys import generate_identity

CONTEXT = "https://vouch-protocol.com/attribution/v1"
MANIFEST_TYPE = "VouchAttributionManifest"
ATTESTATION_TYPE = "VouchAuthorshipAttestation"

SOURCE_AI = "ai-assistant"
SOURCE_HUMAN = "human"
SOURCE_PREEXISTING = "preexisting"


# ----------------------------------------------------------------------------
# Key helpers (Ed25519 <-> JWK), matching the convention used by Signer.
# ----------------------------------------------------------------------------

def _priv_from_jwk(jwk_json: str) -> Ed25519PrivateKey:
    from jwcrypto.common import base64url_decode

    data = json.loads(jwk_json)
    if data.get("kty") != "OKP" or data.get("crv") != "Ed25519":
        raise ValueError("Attribution keys must be Ed25519 (OKP, crv=Ed25519)")
    seed = base64url_decode(data["d"])
    return Ed25519PrivateKey.from_private_bytes(seed)


def _pub_from_jwk(jwk_json: str) -> Ed25519PublicKey:
    from jwcrypto.common import base64url_decode

    data = json.loads(jwk_json)
    if data.get("kty") != "OKP" or data.get("crv") != "Ed25519":
        raise ValueError("Attribution keys must be Ed25519 (OKP, crv=Ed25519)")
    x = base64url_decode(data["x"])
    return Ed25519PublicKey.from_public_bytes(x)


def _did_key_from_pub_jwk(jwk_json: str) -> str:
    """Derive a did:key from an Ed25519 public-key JWK."""
    from jwcrypto.common import base64url_decode
    from . import multikey

    data = json.loads(jwk_json)
    raw = base64url_decode(data["x"])
    return "did:key:" + multikey.encode_ed25519_public(raw)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _split_lines(text: str) -> List[str]:
    # Keep it simple and deterministic: split on newlines, drop a single
    # trailing empty element so a file ending in "\n" is not counted as an
    # extra blank line. Line numbers are 1-based for humans.
    if text == "":
        return []
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ----------------------------------------------------------------------------
# Per-file authorship tracking.
# ----------------------------------------------------------------------------

@dataclass
class _FileState:
    """Authorship aligned to the current snapshot of one file."""

    snapshot: str
    # One entry per line of `snapshot`: {"source": ..., "model": ...|None}
    authorship: List[Dict[str, Optional[str]]] = field(default_factory=list)


def _retag(
    before: str,
    after: str,
    prior: List[Dict[str, Optional[str]]],
    new_tag: Optional[Dict[str, Optional[str]]],
) -> List[Dict[str, Optional[str]]]:
    """
    Diff `before` -> `after` line by line. Equal lines carry their prior tag.
    Inserted or replaced lines take `new_tag`. Returns authorship aligned to
    `after`. If `new_tag` is None, changed lines are left untagged (used by the
    caller to mark residual human edits separately).
    """
    before_lines = _split_lines(before)
    after_lines = _split_lines(after)
    if len(prior) != len(before_lines):
        # Prior is stale or absent; treat all before-lines as preexisting.
        prior = [{"source": SOURCE_PREEXISTING, "model": None} for _ in before_lines]

    result: List[Dict[str, Optional[str]]] = []
    sm = difflib.SequenceMatcher(a=before_lines, b=after_lines, autojunk=False)
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            for k in range(j2 - j1):
                result.append(dict(prior[i1 + k]))
        elif op in ("insert", "replace"):
            tag = new_tag if new_tag is not None else {"source": SOURCE_HUMAN, "model": None}
            for _ in range(j1, j2):
                result.append(dict(tag))
        # 'delete' contributes no lines to `after`
    return result


class AttributionSession:
    """
    A signing session for one stretch of mixed human/AI editing. Holds an
    AI-session identity (its own DID and key) that attests AI-authored regions.
    The human signs the final manifest with a separate key, so neither party
    can mint the other's attribution.

    The session persists its AI key and per-file state under `session_dir`
    (default: <repo>/.vouch/attribution/<session_id>), with the private key
    written 0600.
    """

    def __init__(
        self,
        session_dir: str | os.PathLike[str],
        ai_did: Optional[str] = None,
        ai_private_key_jwk: Optional[str] = None,
        ai_public_key_jwk: Optional[str] = None,
        model: Optional[str] = None,
    ):
        self.dir = Path(session_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.model = model
        self._files: Dict[str, _FileState] = {}

        if ai_did and ai_private_key_jwk and ai_public_key_jwk:
            self.ai_did = ai_did
            self.ai_private_key_jwk = ai_private_key_jwk
            self.ai_public_key_jwk = ai_public_key_jwk
        else:
            self._load_or_create_ai_identity()

        self._priv = _priv_from_jwk(self.ai_private_key_jwk)
        self._load_state()

    # -- AI session identity ------------------------------------------------

    def _identity_path(self) -> Path:
        return self.dir / "ai-session.json"

    def _load_or_create_ai_identity(self) -> None:
        path = self._identity_path()
        if path.exists():
            data = json.loads(path.read_text())
            self.ai_did = data["did"]
            self.ai_private_key_jwk = data["privateKeyJwk"]
            self.ai_public_key_jwk = data["publicKeyJwk"]
            return
        # A fresh ephemeral did:key for this session. In a stronger deployment
        # this key is held by the Identity Sidecar or delegated from the AI
        # vendor's root; here it is generated locally and stored 0600.
        ident = generate_identity()
        self.ai_did = ident.did or _did_key_from_pub_jwk(ident.public_key_jwk)
        self.ai_private_key_jwk = ident.private_key_jwk
        self.ai_public_key_jwk = ident.public_key_jwk
        path.write_text(json.dumps({
            "did": self.ai_did,
            "privateKeyJwk": self.ai_private_key_jwk,
            "publicKeyJwk": self.ai_public_key_jwk,
            "model": self.model,
        }))
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError:  # pragma: no cover - non-POSIX
            pass

    # -- persisted per-file state ------------------------------------------

    def _state_path(self) -> Path:
        return self.dir / "state.json"

    def _load_state(self) -> None:
        path = self._state_path()
        if not path.exists():
            return
        data = json.loads(path.read_text())
        for rel, st in data.get("files", {}).items():
            self._files[rel] = _FileState(snapshot=st["snapshot"], authorship=st["authorship"])

    def _save_state(self) -> None:
        data = {"files": {
            rel: {"snapshot": fs.snapshot, "authorship": fs.authorship}
            for rel, fs in self._files.items()
        }}
        self._state_path().write_text(json.dumps(data))

    # -- recording AI edits -------------------------------------------------

    def record_edit(
        self,
        path: str,
        after_content: str,
        before_content: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record that the AI assistant produced `after_content` for `path`,
        having started from `before_content` (the assistant's Edit old_string
        context, or the prior session snapshot, or empty for a new file).

        Returns a signed authorship attestation for this edit.
        """
        model = model or self.model
        prior_state = self._files.get(path)
        snapshot = prior_state.snapshot if prior_state else None
        snapshot_tags = prior_state.authorship if prior_state else []
        if before_content is None:
            before_content = snapshot if snapshot is not None else ""

        # Step 1: reconcile any human drift. If the file changed between the
        # last AI edit and this one without coming through the assistant, those
        # lines are the human's. This aligns authorship to `before_content`.
        if snapshot is not None and before_content != snapshot:
            interim = _retag(snapshot, before_content, snapshot_tags, None)
        elif snapshot is not None:
            interim = snapshot_tags
        else:
            interim = [{"source": SOURCE_PREEXISTING, "model": None}
                       for _ in _split_lines(before_content)]

        # Step 2: tag the assistant's own change as AI.
        authorship = _retag(
            before_content,
            after_content,
            interim,
            {"source": SOURCE_AI, "model": model},
        )
        self._files[path] = _FileState(snapshot=after_content, authorship=authorship)
        self._save_state()

        attestation = {
            "@context": CONTEXT,
            "type": ATTESTATION_TYPE,
            "session": self.ai_did,
            "path": path,
            "model": model,
            "sha256": _sha256_text(after_content),
            "aiLines": _ranges_for_source(authorship, SOURCE_AI),
            "recordedAt": _now_iso(),
        }
        proof = data_integrity.build_proof(
            attestation, self._priv, f"{self.ai_did}#attribution"
        )
        attestation["proof"] = proof
        self._append_ledger(attestation)
        return attestation

    def _append_ledger(self, attestation: Dict[str, Any]) -> None:
        with (self.dir / "ledger.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(attestation) + "\n")

    # -- finalising into a signed manifest ---------------------------------

    def finalize(
        self,
        files: Dict[str, str],
        human_signer,
        commit: str = "working-tree",
    ) -> Dict[str, Any]:
        """
        Build and sign the Attribution Manifest for `files` (a mapping of path
        -> final committed content). Any line that changed on disk since the
        last AI edit is attributed to the human. `human_signer` is a
        vouch.Signer; it signs the whole manifest with the human's key.
        """
        manifest_files: List[Dict[str, Any]] = []
        ai_attestations: List[Dict[str, Any]] = []

        for path, final_content in files.items():
            st = self._files.get(path)
            if st is None:
                # File the AI never touched: entirely the human's, or
                # preexisting if it equals nothing we tracked. Mark as human.
                authorship = [{"source": SOURCE_HUMAN, "model": None}
                              for _ in _split_lines(final_content)]
            else:
                # Residual diff: snapshot -> final. Changed lines = human.
                authorship = _retag(st.snapshot, final_content, st.authorship, None)
                # Re-sign the AI view of this file as it stood at last AI edit.
                att = {
                    "@context": CONTEXT,
                    "type": ATTESTATION_TYPE,
                    "session": self.ai_did,
                    "path": path,
                    "model": self.model,
                    "sha256": _sha256_text(final_content),
                    "aiLines": _ranges_for_source(authorship, SOURCE_AI),
                    "recordedAt": _now_iso(),
                }
                att["proof"] = data_integrity.build_proof(
                    att, self._priv, f"{self.ai_did}#attribution"
                )
                if att["aiLines"]:
                    ai_attestations.append(att)

            regions = _collapse_regions(authorship, human_signer.get_did(), self.ai_did)
            manifest_files.append({
                "path": path,
                "sha256": _sha256_text(final_content),
                "lineCount": len(_split_lines(final_content)),
                "regions": regions,
            })

        manifest = {
            "@context": CONTEXT,
            "type": MANIFEST_TYPE,
            "commit": commit,
            "createdBy": human_signer.get_did(),
            "aiSession": {
                "did": self.ai_did,
                "model": self.model,
                "publicKeyJwk": json.loads(self.ai_public_key_jwk),
            },
            "files": manifest_files,
            "aiAttestations": ai_attestations,
            "createdAt": _now_iso(),
        }
        human_priv = _priv_from_jwk(_signer_private_jwk(human_signer))
        manifest["proof"] = data_integrity.build_proof(
            manifest, human_priv, f"{human_signer.get_did()}#vouch"
        )
        return manifest


def _signer_private_jwk(human_signer) -> str:
    """Pull the private JWK out of a vouch.Signer for proof building."""
    key = getattr(human_signer, "_key", None)
    if key is None:
        raise ValueError("human_signer does not expose a private key")
    return key.export_private() if hasattr(key, "export_private") else key.export()


# ----------------------------------------------------------------------------
# Region helpers.
# ----------------------------------------------------------------------------

def _ranges_for_source(authorship: List[Dict[str, Optional[str]]], source: str) -> List[List[int]]:
    """1-based inclusive [start, end] line ranges matching `source`."""
    ranges: List[List[int]] = []
    start: Optional[int] = None
    for idx, tag in enumerate(authorship, start=1):
        if tag["source"] == source:
            if start is None:
                start = idx
        else:
            if start is not None:
                ranges.append([start, idx - 1])
                start = None
    if start is not None:
        ranges.append([start, len(authorship)])
    return ranges


def _collapse_regions(
    authorship: List[Dict[str, Optional[str]]],
    human_did: str,
    ai_did: str,
) -> List[Dict[str, Any]]:
    """Collapse consecutive same-author lines into manifest regions."""
    regions: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    for idx, tag in enumerate(authorship, start=1):
        source = tag["source"]
        if source == SOURCE_AI:
            author = ai_did
        elif source == SOURCE_HUMAN:
            author = human_did
        else:
            author = None
        key = (source, author, tag.get("model"))
        if cur is not None and cur["_key"] == key:
            cur["endLine"] = idx
        else:
            if cur is not None:
                cur.pop("_key")
                regions.append(cur)
            cur = {
                "_key": key,
                "startLine": idx,
                "endLine": idx,
                "source": source,
                "author": author,
                "model": tag.get("model"),
            }
    if cur is not None:
        cur.pop("_key")
        regions.append(cur)
    return regions


# ----------------------------------------------------------------------------
# Verification and blame.
# ----------------------------------------------------------------------------

@dataclass
class VerificationResult:
    ok: bool
    reasons: List[str] = field(default_factory=list)


def verify_manifest(
    manifest: Dict[str, Any],
    human_public_key_jwk: str,
    ai_public_key_jwk: Optional[str] = None,
    files_on_disk: Optional[Dict[str, str]] = None,
) -> VerificationResult:
    """
    Verify an Attribution Manifest:

      1. The human Data Integrity proof over the whole manifest.
      2. Every AI attestation against the AI-session key.
      3. Every AI region in the manifest is backed by an AI attestation
         (an AI region cannot exist without the AI signature).
      4. Regions cover the whole file with no gaps or overlaps (completeness,
         so a buggy region cannot hide as unattributed).
      5. If `files_on_disk` is given, file hashes match the current bytes.
    """
    reasons: List[str] = []

    # 1. Human proof.
    try:
        if not data_integrity.verify_proof(manifest, _pub_from_jwk(human_public_key_jwk)):
            reasons.append("human proof signature invalid")
    except Exception as exc:  # malformed proof
        reasons.append(f"human proof error: {exc}")

    ai_pub_jwk = ai_public_key_jwk
    if ai_pub_jwk is None:
        sess = manifest.get("aiSession", {})
        if sess.get("publicKeyJwk"):
            ai_pub_jwk = json.dumps(sess["publicKeyJwk"])

    # 2. AI attestations.
    ai_covered: Dict[str, List[Tuple[int, int]]] = {}
    if manifest.get("aiAttestations"):
        if ai_pub_jwk is None:
            reasons.append("AI attestations present but no AI public key to check them")
        else:
            ai_pub = _pub_from_jwk(ai_pub_jwk)
            for att in manifest["aiAttestations"]:
                try:
                    if not data_integrity.verify_proof(att, ai_pub):
                        reasons.append(f"AI attestation proof invalid for {att.get('path')}")
                        continue
                except Exception as exc:
                    reasons.append(f"AI attestation error for {att.get('path')}: {exc}")
                    continue
                ai_covered.setdefault(att["path"], []).extend(
                    (r[0], r[1]) for r in att.get("aiLines", [])
                )

    # 3, 4, 5 per file.
    for f in manifest.get("files", []):
        path = f["path"]
        regions = sorted(f.get("regions", []), key=lambda r: r["startLine"])
        # Completeness + no overlap.
        expected = 1
        for r in regions:
            if r["startLine"] != expected:
                reasons.append(f"{path}: gap or overlap at line {expected}")
            expected = r["endLine"] + 1
        if f.get("lineCount", expected - 1) != expected - 1:
            reasons.append(f"{path}: regions do not cover all {f.get('lineCount')} lines")
        # AI regions must be backed by an attestation.
        backed = ai_covered.get(path, [])
        for r in regions:
            if r["source"] == SOURCE_AI:
                if not _within_any(r["startLine"], r["endLine"], backed):
                    reasons.append(
                        f"{path}: AI region {r['startLine']}-{r['endLine']} "
                        "has no signed AI attestation"
                    )
        # Content hash.
        if files_on_disk is not None and path in files_on_disk:
            if _sha256_text(files_on_disk[path]) != f.get("sha256"):
                reasons.append(f"{path}: content hash does not match current file")

    return VerificationResult(ok=not reasons, reasons=reasons)


def _within_any(start: int, end: int, ranges: List[Tuple[int, int]]) -> bool:
    for a, b in ranges:
        if a <= start and end <= b:
            return True
    # Allow union coverage across multiple attested ranges.
    covered = set()
    for a, b in ranges:
        covered.update(range(a, b + 1))
    return all(line in covered for line in range(start, end + 1))


def blame(manifest: Dict[str, Any], path: str) -> List[Dict[str, Any]]:
    """
    Return per-line authorship for `path`: a list of
    {"line": n, "source": ..., "author": ..., "model": ...}.
    """
    out: List[Dict[str, Any]] = []
    for f in manifest.get("files", []):
        if f["path"] != path:
            continue
        for r in f.get("regions", []):
            for line in range(r["startLine"], r["endLine"] + 1):
                out.append({
                    "line": line,
                    "source": r["source"],
                    "author": r.get("author"),
                    "model": r.get("model"),
                })
    return out


def summarize(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Aggregate line counts by source across all files."""
    totals = {SOURCE_AI: 0, SOURCE_HUMAN: 0, SOURCE_PREEXISTING: 0}
    for f in manifest.get("files", []):
        for r in f.get("regions", []):
            n = r["endLine"] - r["startLine"] + 1
            totals[r["source"]] = totals.get(r["source"], 0) + n
    total = sum(totals.values()) or 1
    return {
        "lines": totals,
        "aiPercent": round(100 * totals[SOURCE_AI] / total, 1),
        "humanPercent": round(100 * totals[SOURCE_HUMAN] / total, 1),
    }
