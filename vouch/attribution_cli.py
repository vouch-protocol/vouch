"""CLI handlers for `vouch attribute` (per-region human/AI code attribution)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Optional

from . import attribution as attr


# ANSI styling, matched to the rest of the CLI's tone.
_AI = "\033[95m"      # magenta for machine
_HU = "\033[96m"      # cyan for human
_PRE = "\033[2m"      # dim for preexisting
_OK = "\033[92m"
_BAD = "\033[91m"
_END = "\033[0m"


def _repo_root() -> Path:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        )
        return Path(out.stdout.strip())
    except Exception:
        return Path.cwd()


def _session_dir(session: Optional[str] = None) -> Path:
    sid = session or os.environ.get("VOUCH_ATTRIBUTION_SESSION", "current")
    return _repo_root() / ".vouch" / "attribution" / sid


def _open_session(session: Optional[str] = None, model: Optional[str] = None) -> attr.AttributionSession:
    return attr.AttributionSession(_session_dir(session), model=model)


def _read(path: str) -> str:
    p = Path(path)
    return p.read_text(encoding="utf-8") if p.exists() else ""


def _rel(path: str) -> str:
    try:
        return str(Path(path).resolve().relative_to(_repo_root()))
    except Exception:
        return path


# ---------------------------------------------------------------------------
# record / hook
# ---------------------------------------------------------------------------

def cmd_attr_record(args) -> int:
    """Record one AI edit (scripting / testing entry point)."""
    after = args.after if args.after is not None else _read(args.after_file)
    before = None
    if args.before is not None:
        before = args.before
    elif args.before_file:
        before = _read(args.before_file)
    session = _open_session(args.session, args.model)
    session.record_edit(_rel(args.path), after, before, model=args.model)
    print(f"recorded AI edit: {_rel(args.path)}")
    return 0


def cmd_attr_hook(args) -> int:
    """
    Read a Claude Code PostToolUse event from stdin and record the AI edit.
    Wire it to Edit and Write. Never fails the tool call: on any problem it
    exits 0 so the assistant is not disrupted.
    """
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0
    try:
        tool = event.get("tool_name", "")
        tin = event.get("tool_input", {}) or {}
        path = tin.get("file_path")
        if not path or tool not in ("Edit", "Write", "MultiEdit"):
            return 0
        rel = _rel(path)
        after = _read(path)  # PostToolUse fires after the edit is applied
        before: Optional[str] = None
        if tool == "Edit":
            old = tin.get("old_string", "")
            new = tin.get("new_string", "")
            if old or new:
                # Reconstruct the pre-edit content so the new_string lines are
                # diffed as AI-authored.
                before = after.replace(new, old, 1) if new else after
        elif tool == "Write":
            before = None  # session falls back to last snapshot or empty
        model = event.get("model") or os.environ.get("VOUCH_AI_MODEL")
        session = _open_session(args.session, model)
        session.record_edit(rel, after, before, model=model)
    except Exception:
        return 0  # never break the assistant
    return 0


# ---------------------------------------------------------------------------
# finalize
# ---------------------------------------------------------------------------

def _load_human_signer():
    from .signer import Signer
    from .keys import KeyManager

    try:
        did = subprocess.run(
            ["git", "config", "--get", "vouch.did"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except Exception:
        did = ""
    if not did:
        raise SystemExit(
            f"{_BAD}No Vouch identity configured for git.{_END} "
            "Run `vouch git init` first, or set git config vouch.did."
        )
    ident = KeyManager().load_identity(did)
    return Signer(private_key=ident.private_key_jwk, did=ident.did)


def cmd_attr_finalize(args) -> int:
    session = _open_session(args.session)
    if not session._files:
        print("No AI edits recorded for this session; nothing to finalize.")
        return 0
    signer = _load_human_signer()
    files: Dict[str, str] = {}
    for rel in session._files:
        files[rel] = _read(str(_repo_root() / rel))
    manifest = session.finalize(files, signer, commit=args.commit)

    out = Path(args.out) if args.out else _session_dir(args.session) / "manifest.json"
    out.write_text(json.dumps(manifest, indent=2))
    s = attr.summarize(manifest)
    print(f"{_OK}Attribution manifest written:{_END} {out}")
    print(f"  files      : {len(manifest['files'])}")
    print(f"  {_AI}AI lines{_END}   : {s['lines'][attr.SOURCE_AI]} ({s['aiPercent']}%)")
    print(f"  {_HU}human lines{_END}: {s['lines'][attr.SOURCE_HUMAN]} ({s['humanPercent']}%)")
    print(f"  signed by  : {manifest['createdBy']}  +  {manifest['aiSession']['did']}")
    return 0


# ---------------------------------------------------------------------------
# blame / verify
# ---------------------------------------------------------------------------

def _load_manifest(args) -> dict:
    path = Path(args.manifest) if args.manifest else _session_dir(
        getattr(args, "session", None)
    ) / "manifest.json"
    if not path.exists():
        raise SystemExit(f"{_BAD}No manifest at {path}.{_END} Run `vouch attribute finalize` first.")
    return json.loads(path.read_text())


def cmd_attr_blame(args) -> int:
    manifest = _load_manifest(args)
    rel = _rel(args.path)
    lines = attr.blame(manifest, rel)
    if not lines:
        print(f"No attribution for {rel} in this manifest.")
        return 1
    content = _read(str(_repo_root() / rel)).split("\n")
    for entry in lines:
        n = entry["line"]
        src = entry["source"]
        text = content[n - 1] if n - 1 < len(content) else ""
        if src == attr.SOURCE_AI:
            tag = f"{_AI}AI  {_END}"
        elif src == attr.SOURCE_HUMAN:
            tag = f"{_HU}human{_END}"
        else:
            tag = f"{_PRE}prior{_END}"
        print(f"{tag} {n:>4} | {text}")
    return 0


def cmd_attr_verify(args) -> int:
    manifest = _load_manifest(args)
    human_pub = None
    # Human public key: from --human-key, else resolve from git DID document is
    # out of scope here; require the key or read from the local identity.
    if args.human_key:
        human_pub = _read(args.human_key)
    else:
        from .keys import KeyManager
        try:
            ident = KeyManager().load_identity(manifest["createdBy"])
            human_pub = ident.public_key_jwk
        except Exception:
            raise SystemExit(
                f"{_BAD}Need the human public key to verify.{_END} "
                "Pass --human-key <file.jwk>."
            )
    files = None
    if args.check_files:
        files = {f["path"]: _read(str(_repo_root() / f["path"])) for f in manifest["files"]}
    res = attr.verify_manifest(manifest, human_pub, files_on_disk=files)
    if res.ok:
        s = attr.summarize(manifest)
        print(f"{_OK}VERIFIED{_END}  human + AI signatures valid, regions complete.")
        print(f"  {_AI}AI{_END} {s['aiPercent']}%   {_HU}human{_END} {s['humanPercent']}%")
        return 0
    print(f"{_BAD}FAILED{_END}")
    for r in res.reasons:
        print(f"  - {r}")
    return 1


# ---------------------------------------------------------------------------
# argparse wiring (called from cli.py)
# ---------------------------------------------------------------------------

def register(subparsers) -> None:
    p = subparsers.add_parser(
        "attribute",
        help="Per-region human/AI code authorship attribution (PAD-061)",
    )
    sub = p.add_subparsers(dest="attr_command", help="Attribution commands")

    pr = sub.add_parser("record", help="Record one AI edit")
    pr.add_argument("path")
    pr.add_argument("--after")
    pr.add_argument("--after-file")
    pr.add_argument("--before")
    pr.add_argument("--before-file")
    pr.add_argument("--model")
    pr.add_argument("--session")

    ph = sub.add_parser("hook", help="Record from a Claude Code PostToolUse event on stdin")
    ph.add_argument("--session")

    pf = sub.add_parser("finalize", help="Sign the attribution manifest for this session")
    pf.add_argument("--commit", default="working-tree")
    pf.add_argument("--out")
    pf.add_argument("--session")

    pb = sub.add_parser("blame", help="Show per-line authorship for a file")
    pb.add_argument("path")
    pb.add_argument("--manifest")
    pb.add_argument("--session")

    pv = sub.add_parser("verify", help="Verify an attribution manifest")
    pv.add_argument("--manifest")
    pv.add_argument("--human-key", help="Human public key JWK file")
    pv.add_argument("--check-files", action="store_true", help="Compare hashes to files on disk")
    pv.add_argument("--session")

    return p


def dispatch(args, parser_help) -> int:
    cmd = getattr(args, "attr_command", None)
    if cmd == "record":
        return cmd_attr_record(args)
    if cmd == "hook":
        return cmd_attr_hook(args)
    if cmd == "finalize":
        return cmd_attr_finalize(args)
    if cmd == "blame":
        return cmd_attr_blame(args)
    if cmd == "verify":
        return cmd_attr_verify(args)
    parser_help()
    return 0
