"""
Vouch Protocol Onboarding Wizard.

Implements the six-step adoption path from the Vouch Protocol paper, section
12.2, as an interactive CLI wizard. See ``docs/onboarding-wizard-spec.md`` for
the design contract that both this module and the website's /onboard stepper
satisfy.

Public entrypoint is :func:`run_wizard`, called from ``vouch.cli.cmd_onboard``.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from vouch.keys import KeyManager, generate_identity

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

STATE_PATH = Path.home() / ".vouch" / "onboarding.json"

STEP_SLUGS = ["identity", "tier", "allowlist", "toolwire", "verifier", "heartbeat"]

TIER_CHOICES = ["edge", "standard", "regulated"]
LANG_CHOICES = ["python", "typescript", "go"]

ALLOWLIST_PRESETS: Dict[str, List[Dict[str, Any]]] = {
    "read-only": [
        {"name": "search.web", "description": "Read-only web search", "scope": "https://*"},
        {"name": "read.file", "description": "Read a local file", "scope": "fs:read:./**"},
    ],
    "read-write-scoped": [
        {"name": "search.web", "description": "Read-only web search", "scope": "https://*"},
        {"name": "read.file", "description": "Read a local file", "scope": "fs:read:./**"},
        {
            "name": "write.file",
            "description": "Write to an allow-listed directory",
            "scope": "fs:write:./out/**",
            "requires": {"max_delegation_depth": 1},
        },
        {
            "name": "http.post",
            "description": "POST to a known partner API",
            "scope": "https://api.partner.example/**",
            "requires": {"max_delegation_depth": 0},
        },
    ],
    "regulated": [
        {
            "name": "kyc.lookup",
            "description": "Look up a verified customer record",
            "scope": "kyc:read:customers",
            "requires": {"max_delegation_depth": 0, "audit": "required"},
        },
        {
            "name": "ledger.read",
            "description": "Read ledger balance",
            "scope": "ledger:read:accounts/*",
            "requires": {"max_delegation_depth": 0, "audit": "required"},
        },
        {
            "name": "ledger.transfer",
            "description": "Initiate a transfer (heartbeat-gated)",
            "scope": "ledger:write:transfers",
            "requires": {
                "max_delegation_depth": 0,
                "audit": "required",
                "heartbeat_quorum": 3,
            },
        },
    ],
}


@dataclass
class StepRecord:
    status: str = "pending"  # pending | done | skipped
    completed_at: Optional[str] = None
    note: Optional[str] = None


@dataclass
class OnboardState:
    version: int = 1
    started_at: str = field(default_factory=lambda: _now_iso())
    completed_at: Optional[str] = None
    domain: Optional[str] = None
    did: Optional[str] = None
    tier: Optional[str] = None
    allowlist_path: Optional[str] = None
    allowlist_preset: Optional[str] = None
    toolwire_lang: Optional[str] = None
    verifier_lang: Optional[str] = None
    heartbeat_quorum: int = 1
    out_dir: str = "."
    steps: Dict[str, StepRecord] = field(
        default_factory=lambda: {s: StepRecord() for s in STEP_SLUGS}
    )

    def to_json(self) -> Dict[str, Any]:
        d = dataclasses.asdict(self)
        d["steps"] = {k: dataclasses.asdict(v) for k, v in self.steps.items()}
        return d

    @classmethod
    def from_json(cls, raw: Dict[str, Any]) -> "OnboardState":
        steps_raw = raw.pop("steps", {}) or {}
        steps = {s: StepRecord(**(steps_raw.get(s) or {})) for s in STEP_SLUGS}
        st = cls(**{k: v for k, v in raw.items() if k in {f.name for f in dataclasses.fields(cls)}})
        st.steps = steps
        return st


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_state() -> Optional[OnboardState]:
    if not STATE_PATH.exists():
        return None
    try:
        with open(STATE_PATH, "r") as f:
            return OnboardState.from_json(json.load(f))
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def save_state(state: OnboardState) -> None:
    STATE_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = STATE_PATH.with_suffix(".json.tmp")
    with open(tmp, "w") as f:
        json.dump(state.to_json(), f, indent=2)
    os.replace(tmp, STATE_PATH)


def reset_state() -> bool:
    if STATE_PATH.exists():
        STATE_PATH.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# I/O abstraction (so the website preview can drive the same engine)
# ---------------------------------------------------------------------------


@dataclass
class WizardIO:
    """Abstracts prompts and output so non-interactive and dry-run modes can
    drive the engine without a terminal."""

    interactive: bool = True
    dry_run: bool = False
    answers: Dict[str, str] = field(default_factory=dict)
    written: Dict[str, str] = field(default_factory=dict)
    out: Callable[[str], None] = print

    def ask(self, key: str, prompt: str, default: Optional[str] = None,
            choices: Optional[List[str]] = None) -> str:
        if key in self.answers:
            return self.answers[key]
        if not self.interactive:
            if default is not None:
                return default
            raise ValueError(
                f"Non-interactive run missing required input: {key}. "
                f"Pass it as a CLI flag."
            )
        suffix = f" [{default}]" if default else ""
        if choices:
            suffix = f" ({'/'.join(choices)}){suffix}"
        while True:
            raw = input(f"{prompt}{suffix}: ").strip()
            if not raw and default is not None:
                return default
            if choices and raw not in choices:
                print(f"  Please choose one of: {', '.join(choices)}")
                continue
            if raw:
                return raw

    def write(self, path: str, content: str) -> None:
        """Write content to ``path`` (relative to out_dir resolution at call
        site), or stash it in :attr:`written` under dry-run."""
        if self.dry_run:
            self.written[path] = content
            self.out(f"  [dry-run] would write {path} ({len(content)} bytes)")
            return
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        self.out(f"  wrote {path}")


# ---------------------------------------------------------------------------
# Banner and helpers
# ---------------------------------------------------------------------------


BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║  Vouch Protocol Onboarding Wizard                                ║
║  Adoption path: identity to heartbeat in six steps               ║
╚══════════════════════════════════════════════════════════════════╝
"""


def _step_header(num: int, title: str, io: WizardIO) -> None:
    io.out("")
    io.out(f"─── Step {num} of 6: {title} ───")


def _did_from_domain(domain: str) -> str:
    return f"did:web:{domain.strip().lower()}"


def _ed25519_did_document(did: str, public_key_jwk: str) -> Dict[str, Any]:
    pk = json.loads(public_key_jwk)
    return {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#key-1",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": {
                    "kty": pk.get("kty"),
                    "crv": pk.get("crv"),
                    "x": pk.get("x"),
                },
            }
        ],
        "authentication": [f"{did}#key-1"],
        "assertionMethod": [f"{did}#key-1"],
    }


# ---------------------------------------------------------------------------
# Step implementations
# ---------------------------------------------------------------------------


def step_identity(state: OnboardState, io: WizardIO) -> None:
    _step_header(1, "Identity (generate issuer DID)", io)
    domain = io.ask(
        "domain",
        "Domain that will host the DID Document (e.g. agent.acme.example)",
        default=state.domain,
    )
    state.domain = domain
    state.did = _did_from_domain(domain)

    kp = generate_identity(domain)
    # KeyPair from generate_identity already has did:web:<domain>; reuse.
    if not io.dry_run:
        km = KeyManager()
        try:
            km.save_identity(kp, password=None)
        except Exception as e:
            io.out(f"  (skipped key save: {e})")

    did_doc = _ed25519_did_document(state.did, kp.public_key_jwk)
    out_path = str(Path(state.out_dir) / "did.json")
    io.write(out_path, json.dumps(did_doc, indent=2))

    io.out(f"  DID:        {state.did}")
    io.out(f"  Publish at: https://{domain}/.well-known/did.json")
    if not io.dry_run:
        io.out(f"  Private key stored at ~/.vouch/keys/ (encrypt with passphrase via `vouch init`)")


def step_tier(state: OnboardState, io: WizardIO) -> None:
    _step_header(2, "Sidecar tier", io)
    io.out("  edge       - in-process signer, lowest latency, single tenant")
    io.out("  standard   - colocated sidecar, KMS-backed, multi-agent")
    io.out("  regulated  - separate VPC, HSM-backed, mandatory heartbeat quorum")
    tier = io.ask("tier", "Tier", default=state.tier or "standard", choices=TIER_CHOICES)
    state.tier = tier
    if tier == "regulated":
        state.heartbeat_quorum = 3
        io.out("  Regulated tier: heartbeat quorum set to 3 (mandatory)")


def step_allowlist(state: OnboardState, io: WizardIO) -> None:
    _step_header(3, "Allow-list (action vocabulary)", io)
    io.out("  Presets:")
    for name, actions in ALLOWLIST_PRESETS.items():
        io.out(f"    {name:<20} {len(actions)} actions")
    preset = io.ask(
        "allowlist_preset",
        "Starter preset",
        default=state.allowlist_preset or ("regulated" if state.tier == "regulated" else "read-write-scoped"),
        choices=list(ALLOWLIST_PRESETS.keys()),
    )
    state.allowlist_preset = preset
    doc = {
        "version": 1,
        "issuer": state.did,
        "tier": state.tier,
        "actions": ALLOWLIST_PRESETS[preset],
    }
    out_path = str(Path(state.out_dir) / "vouch-allowlist.json")
    state.allowlist_path = out_path
    io.write(out_path, json.dumps(doc, indent=2))
    io.out(f"  {len(ALLOWLIST_PRESETS[preset])} actions allow-listed for {state.did}")


def step_toolwire(state: OnboardState, io: WizardIO) -> None:
    _step_header(4, "Wire tool calls to /sign", io)
    lang = io.ask(
        "toolwire_lang", "Language", default=state.toolwire_lang or "python", choices=LANG_CHOICES
    )
    state.toolwire_lang = lang
    snippet = _TOOLWIRE_SNIPPETS[lang].format(did=state.did or "did:web:agent.acme.example")
    ext = {"python": "py", "typescript": "ts", "go": "go"}[lang]
    out_path = str(Path(state.out_dir) / f"vouch-toolwire.{ext}")
    io.write(out_path, snippet)


def step_verifier(state: OnboardState, io: WizardIO) -> None:
    _step_header(5, "Verifier at the API boundary", io)
    lang = io.ask(
        "verifier_lang", "Language", default=state.verifier_lang or state.toolwire_lang or "python",
        choices=LANG_CHOICES,
    )
    state.verifier_lang = lang
    snippet = _VERIFIER_SNIPPETS[lang].format(
        did=state.did or "did:web:agent.acme.example",
        allowlist=state.allowlist_path or "./vouch-allowlist.json",
    )
    ext = {"python": "py", "typescript": "ts", "go": "go"}[lang]
    out_path = str(Path(state.out_dir) / f"vouch-verifier.{ext}")
    io.write(out_path, snippet)


def step_heartbeat(state: OnboardState, io: WizardIO) -> None:
    _step_header(6, "Heartbeat validator (long-running agents)", io)
    if state.tier != "regulated":
        deploy = io.ask(
            "heartbeat_deploy",
            "Deploy a heartbeat validator? (recommended for any agent running > 5 min)",
            default="yes",
            choices=["yes", "no"],
        )
        if deploy == "no":
            state.steps["heartbeat"] = StepRecord(status="skipped", completed_at=_now_iso(),
                                                  note="user declined")
            io.out("  Skipped. You can re-run `vouch onboard --resume` later to add this.")
            return
    quorum = state.heartbeat_quorum if state.tier == "regulated" else 1
    state.heartbeat_quorum = quorum
    manifest = _HEARTBEAT_MANIFEST.format(
        did=state.did or "did:web:agent.acme.example",
        quorum=quorum,
        replicas=quorum,
    )
    out_path = str(Path(state.out_dir) / "vouch-heartbeat.yaml")
    io.write(out_path, manifest)
    io.out(f"  Quorum: {quorum} validator{'s' if quorum != 1 else ''}")


STEPS: List[Callable[[OnboardState, WizardIO], None]] = [
    step_identity,
    step_tier,
    step_allowlist,
    step_toolwire,
    step_verifier,
    step_heartbeat,
]


# ---------------------------------------------------------------------------
# Snippets (kept short; production users will adapt these)
# ---------------------------------------------------------------------------


_TOOLWIRE_SNIPPETS = {
    "python": '''"""Vouch tool-call wrapper.

Wrap your agent's tool dispatcher so every call mints a Vouch credential
against the Sidecar's /sign endpoint before the underlying tool runs.
"""
import httpx
from typing import Any, Callable, Dict

SIDECAR_URL = "http://localhost:8787/sign"
ISSUER_DID = "{did}"


def vouch_tool(action: str) -> Callable:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Dict[str, Any]) -> Any:
            r = httpx.post(SIDECAR_URL, json={{
                "issuer": ISSUER_DID,
                "action": action,
                "args": kwargs,
            }}, timeout=2.0)
            r.raise_for_status()
            token = r.json()["token"]
            kwargs.setdefault("_vouch_headers", {{}})
            kwargs["_vouch_headers"]["Vouch-Token"] = token
            return fn(*args, **kwargs)
        return wrapped
    return decorator


# Example:
# @vouch_tool("http.post")
# def send_to_partner(url: str, body: dict, _vouch_headers=None): ...
''',
    "typescript": '''/**
 * Vouch tool-call wrapper.
 *
 * Wrap your agent's tool dispatcher so every call mints a Vouch credential
 * against the Sidecar's /sign endpoint before the underlying tool runs.
 */
const SIDECAR_URL = "http://localhost:8787/sign";
const ISSUER_DID = "{did}";

export function vouchTool<F extends (...args: any[]) => any>(action: string, fn: F): F {{
  return (async (...args: any[]) => {{
    const res = await fetch(SIDECAR_URL, {{
      method: "POST",
      headers: {{ "content-type": "application/json" }},
      body: JSON.stringify({{ issuer: ISSUER_DID, action, args }}),
    }});
    if (!res.ok) throw new Error(`Vouch sidecar /sign failed: ${{res.status}}`);
    const {{ token }} = await res.json();
    return fn(...args, {{ "Vouch-Token": token }});
  }}) as F;
}}
''',
    "go": '''// Vouch tool-call wrapper.
//
// Call VouchSign before invoking the underlying tool to mint a credential
// against the Sidecar's /sign endpoint.
package vouchwire

import (
    "bytes"
    "encoding/json"
    "net/http"
)

const (
    SidecarURL = "http://localhost:8787/sign"
    IssuerDID  = "{did}"
)

type signReq struct {{
    Issuer string                 `json:"issuer"`
    Action string                 `json:"action"`
    Args   map[string]interface{{}} `json:"args"`
}}

type signResp struct {{
    Token string `json:"token"`
}}

func VouchSign(action string, args map[string]interface{{}}) (string, error) {{
    body, _ := json.Marshal(signReq{{Issuer: IssuerDID, Action: action, Args: args}})
    resp, err := http.Post(SidecarURL, "application/json", bytes.NewReader(body))
    if err != nil {{
        return "", err
    }}
    defer resp.Body.Close()
    var sr signResp
    if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {{
        return "", err
    }}
    return sr.Token, nil
}}
''',
}


_VERIFIER_SNIPPETS = {
    "python": '''"""Vouch verifier middleware for FastAPI.

Drop this into your API boundary. It verifies the Vouch-Token header on
every request and rejects calls whose action is not in the allow-list.
"""
import json
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from vouch.verifier import Verifier

ISSUER_DID = "{did}"
ALLOWLIST = json.loads(Path("{allowlist}").read_text())
ALLOWED_ACTIONS = {{a["name"] for a in ALLOWLIST["actions"]}}

app = FastAPI()


@app.middleware("http")
async def vouch_middleware(request: Request, call_next):
    token = request.headers.get("Vouch-Token")
    if not token:
        raise HTTPException(401, "Missing Vouch-Token header")
    valid, passport = Verifier.verify(token)
    if not valid or not passport:
        raise HTTPException(401, "Invalid Vouch-Token")
    action = (passport.payload or {{}}).get("action")
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(403, f"Action {{action!r}} not in allow-list")
    request.state.vouch_passport = passport
    return await call_next(request)
''',
    "typescript": '''/**
 * Vouch verifier middleware for Express.
 *
 * Verifies the Vouch-Token header on every request and rejects calls
 * whose action is not in the allow-list.
 */
import {{ readFileSync }} from "node:fs";
import type {{ Request, Response, NextFunction }} from "express";

const ISSUER_DID = "{did}";
const ALLOWLIST = JSON.parse(readFileSync("{allowlist}", "utf-8"));
const ALLOWED = new Set<string>(ALLOWLIST.actions.map((a: any) => a.name));

export function vouchMiddleware(req: Request, res: Response, next: NextFunction) {{
  const token = req.header("Vouch-Token");
  if (!token) return res.status(401).send("Missing Vouch-Token");
  // Pseudo: replace with @vouch-protocol/sdk verify(token, {{ issuer: ISSUER_DID }}).
  const passport = verify(token);
  if (!passport) return res.status(401).send("Invalid Vouch-Token");
  if (!ALLOWED.has(passport.payload.action)) {{
    return res.status(403).send(`Action ${{passport.payload.action}} not allow-listed`);
  }}
  (req as any).vouchPassport = passport;
  next();
}}

function verify(_token: string): any {{
  throw new Error("Wire to @vouch-protocol/sdk verify()");
}}
''',
    "go": '''// Vouch verifier middleware for net/http (Gin-compatible).
package vouchverify

import (
    "encoding/json"
    "net/http"
    "os"
)

const IssuerDID = "{did}"

var allowed map[string]bool

func init() {{
    data, _ := os.ReadFile("{allowlist}")
    var doc struct {{
        Actions []struct {{ Name string `json:"name"` }} `json:"actions"`
    }}
    _ = json.Unmarshal(data, &doc)
    allowed = map[string]bool{{}}
    for _, a := range doc.Actions {{
        allowed[a.Name] = true
    }}
}}

func Middleware(next http.Handler) http.Handler {{
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {{
        token := r.Header.Get("Vouch-Token")
        if token == "" {{
            http.Error(w, "missing Vouch-Token", http.StatusUnauthorized)
            return
        }}
        // Wire to github.com/vouch-protocol/vouch/go/verifier here.
        // passport := verifier.Verify(token, IssuerDID)
        // if passport == nil {{ ...401... }}
        // if !allowed[passport.Action] {{ ...403... }}
        next.ServeHTTP(w, r)
    }})
}}
''',
}


_HEARTBEAT_MANIFEST = """# Vouch Heartbeat validator deployment.
#
# Runs {quorum} validator(s) against issuer {did}. For regulated tier the
# spec requires a quorum of 3 (this manifest reflects that). Each validator
# polls the agent's heartbeat endpoint and votes on session health; a
# quorum of valid votes is required for long-running sessions to continue
# producing credentials.
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vouch-heartbeat
spec:
  replicas: {replicas}
  selector:
    matchLabels: {{ app: vouch-heartbeat }}
  template:
    metadata:
      labels: {{ app: vouch-heartbeat }}
    spec:
      containers:
        - name: validator
          image: ghcr.io/vouch-protocol/heartbeat:latest
          env:
            - name: VOUCH_ISSUER_DID
              value: "{did}"
            - name: VOUCH_QUORUM
              value: "{quorum}"
          ports:
            - containerPort: 8088
"""


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


def _next_step_index(state: OnboardState) -> Optional[int]:
    for i, slug in enumerate(STEP_SLUGS):
        if state.steps[slug].status != "done" and state.steps[slug].status != "skipped":
            return i
    return None


def _print_summary(state: OnboardState, io: WizardIO) -> None:
    io.out("")
    io.out("─── Summary ───")
    io.out(f"  DID:         {state.did}")
    io.out(f"  Tier:        {state.tier}")
    io.out(f"  Allow-list:  {state.allowlist_path} ({state.allowlist_preset})")
    io.out(f"  Tool wrap:   vouch-toolwire.{_ext(state.toolwire_lang)}")
    io.out(f"  Verifier:    vouch-verifier.{_ext(state.verifier_lang)}")
    if state.steps["heartbeat"].status == "done":
        io.out(f"  Heartbeat:   vouch-heartbeat.yaml (quorum {state.heartbeat_quorum})")
    elif state.steps["heartbeat"].status == "skipped":
        io.out("  Heartbeat:   skipped")
    io.out("")
    io.out("Next: commit did.json to your domain at /.well-known/did.json, then deploy.")


def _ext(lang: Optional[str]) -> str:
    return {"python": "py", "typescript": "ts", "go": "go"}.get(lang or "python", "py")


def run_wizard(
    *,
    resume: bool = False,
    reset: bool = False,
    interactive: bool = True,
    dry_run: bool = False,
    out_dir: str = ".",
    preset_answers: Optional[Dict[str, str]] = None,
) -> int:
    """Run the onboarding wizard. Returns 0 on success."""
    if reset:
        if reset_state():
            print("Removed prior onboarding state.")
        else:
            print("No prior onboarding state to remove.")

    state = load_state() if resume or not reset else None
    if state is None:
        state = OnboardState(out_dir=out_dir)
    else:
        state.out_dir = out_dir

    io = WizardIO(
        interactive=interactive,
        dry_run=dry_run,
        answers=dict(preset_answers or {}),
    )

    if interactive:
        io.out(BANNER)
        io.out("Press Ctrl+C any time. Re-run with --resume to pick up where you left off.")
    if state.completed_at:
        io.out(f"Prior run already completed at {state.completed_at}. Use --reset to start over.")
        return 0

    start_at = _next_step_index(state) or 0
    for i in range(start_at, len(STEPS)):
        slug = STEP_SLUGS[i]
        try:
            STEPS[i](state, io)
        except KeyboardInterrupt:
            io.out("\nInterrupted. State saved; resume with `vouch onboard --resume`.")
            save_state(state)
            return 130
        if state.steps[slug].status not in {"skipped"}:
            state.steps[slug] = StepRecord(status="done", completed_at=_now_iso())
        if not dry_run:
            save_state(state)

    state.completed_at = _now_iso()
    if not dry_run:
        save_state(state)
    _print_summary(state, io)
    return 0


# ---------------------------------------------------------------------------
# CLI integration helper (called by vouch.cli.cmd_onboard)
# ---------------------------------------------------------------------------


def cmd_onboard(args: argparse.Namespace) -> int:
    preset: Dict[str, str] = {}
    if getattr(args, "domain", None):
        preset["domain"] = args.domain
    if getattr(args, "tier", None):
        preset["tier"] = args.tier
    if getattr(args, "lang", None):
        preset["toolwire_lang"] = args.lang
        preset["verifier_lang"] = args.lang
    return run_wizard(
        resume=getattr(args, "resume", False),
        reset=getattr(args, "reset", False),
        interactive=not getattr(args, "non_interactive", False),
        dry_run=getattr(args, "dry_run", False),
        out_dir=getattr(args, "out_dir", ".") or ".",
        preset_answers=preset,
    )
