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
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from vouch import multikey
from vouch.keys import MLDSA44, KeyManager, generate_identity

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
    public_key_jwk: Optional[str] = None
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

    def ask(
        self,
        key: str,
        prompt: str,
        default: Optional[str] = None,
        choices: Optional[List[str]] = None,
    ) -> str:
        if key in self.answers:
            return self.answers[key]
        if not self.interactive:
            if default is not None:
                return default
            raise ValueError(
                f"Non-interactive run missing required input: {key}. Pass it as a CLI flag."
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


# A host name, with an optional port written the did:web way (":" as "%3A").
_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?(%3a[0-9]{1,5})?$")


def _did_from_domain(domain: str) -> str:
    """Build the did:web identifier for a host name.

    Raises:
      ValueError: the value is not a plain host name. The DID is written into
        the generated starter files, so anything else is refused here.
    """
    host = domain.strip().lower()
    if not _DOMAIN_RE.match(host) or ".." in host:
        raise ValueError(
            f"{domain!r} is not a domain name. Use a host such as agent.example.com, "
            "with no scheme, path, or spaces."
        )
    return f"did:web:{host}"


def _render(template: str, values: Dict[str, str]) -> str:
    """Fill the ``@@NAME@@`` placeholders of a starter-file template.

    The template is filled in one pass, so a value is never scanned for
    placeholders itself.
    """

    def fill(match: "re.Match[str]") -> str:
        name = match.group(1)
        if name not in values:
            raise ValueError(f"starter template has an unknown placeholder: {match.group(0)}")
        return values[name]

    return re.sub(r"@@([A-Z_]+)@@", fill, template)


def _starter_values(state: OnboardState) -> Dict[str, str]:
    """Values written into the generated tool wrapper and verifier.

    Everything that lands inside code is emitted as a quoted string literal.
    """
    did = state.did or "did:web:agent.acme.example"
    public_key_jwk = state.public_key_jwk
    if not public_key_jwk and state.did:
        public_key_jwk = KeyManager().get_public_key(state.did)
    if not public_key_jwk:
        raise ValueError(
            f"No public key found for {did}. Re-run with --reset to create the identity again."
        )
    jwk_dict = json.loads(public_key_jwk)
    raw_public = base64.urlsafe_b64decode(jwk_dict["x"] + "=" * (-len(jwk_dict["x"]) % 4))
    public_jwk = {"kty": jwk_dict["kty"], "crv": jwk_dict["crv"], "x": jwk_dict["x"]}
    return {
        "DID": did,
        "DID_LITERAL": json.dumps(did),
        "ALLOWLIST_LITERAL": json.dumps(state.allowlist_path or "./vouch-allowlist.json"),
        "PUBLIC_KEY_JWK_LITERAL": repr(json.dumps(public_jwk, separators=(",", ":"))),
        "PUBLIC_KEY_JWK_OBJECT": json.dumps(public_jwk),
        "PUBLIC_KEY_MULTIKEY_LITERAL": json.dumps(multikey.encode_ed25519_public(raw_public)),
    }


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


def _saved_post_quantum_public_key(km: KeyManager, did: str) -> Optional[str]:
    """The identity's saved ML-DSA-44 public key (a Multikey), or None when the
    identity has none or is locked."""
    try:
        key = km.load_identity(did, None).key_for(MLDSA44)
    except (ValueError, FileNotFoundError):
        return None
    return key.public_key if key else None


def step_identity(state: OnboardState, io: WizardIO) -> None:
    _step_header(1, "Identity (generate issuer DID)", io)
    domain = io.ask(
        "domain",
        "Domain that will host the DID Document (e.g. agent.acme.example)",
        default=state.domain,
    )
    state.did = _did_from_domain(domain)
    state.domain = state.did[len("did:web:") :]

    # An identity that already exists for this DID is kept. Generating a new
    # one would replace its private key and orphan a published did.json.
    km = KeyManager()
    existing_key = km.get_public_key(state.did)
    if existing_key:
        state.public_key_jwk = existing_key
        io.out("  Using the identity already in your keystore for this domain")
    else:
        kp = generate_identity(state.domain, post_quantum=True)
        state.public_key_jwk = kp.public_key_jwk
        if not io.dry_run:
            km.save_identity(kp, password=None)

    did_doc = _ed25519_did_document(state.did, state.public_key_jwk)
    post_quantum_key = _saved_post_quantum_public_key(km, state.did)
    if post_quantum_key:
        # The post-quantum key sits in the "#key-2" slot beside the Ed25519 key.
        method = f"{state.did}#key-2"
        did_doc["verificationMethod"].append(
            {
                "id": method,
                "type": "Multikey",
                "controller": state.did,
                "publicKeyMultibase": post_quantum_key,
            }
        )
        did_doc["assertionMethod"].append(method)
        did_doc["@context"].append("https://w3id.org/security/multikey/v1")
    out_path = str(Path(state.out_dir) / "did.json")
    io.write(out_path, json.dumps(did_doc, indent=2))

    io.out(f"  DID:        {state.did}")
    io.out(f"  Publish at: https://{state.domain}/.well-known/did.json")
    if not io.dry_run and not existing_key:
        io.out("  Private key stored at ~/.vouch/keys/ (encrypt with passphrase via `vouch init`)")


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
        default=state.allowlist_preset
        or ("regulated" if state.tier == "regulated" else "read-write-scoped"),
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
    snippet = _render(_TOOLWIRE_SNIPPETS[lang], _starter_values(state))
    ext = {"python": "py", "typescript": "ts", "go": "go"}[lang]
    out_path = str(Path(state.out_dir) / f"vouch-toolwire.{ext}")
    io.write(out_path, snippet)


def step_verifier(state: OnboardState, io: WizardIO) -> None:
    _step_header(5, "Verifier at the API boundary", io)
    lang = io.ask(
        "verifier_lang",
        "Language",
        default=state.verifier_lang or state.toolwire_lang or "python",
        choices=LANG_CHOICES,
    )
    state.verifier_lang = lang
    snippet = _render(_VERIFIER_SNIPPETS[lang], _starter_values(state))
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
            state.steps["heartbeat"] = StepRecord(
                status="skipped", completed_at=_now_iso(), note="user declined"
            )
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
    "python": '''"""Vouch Protocol tool-call wrapper.

Wrap a tool so that every call first asks the sidecar to sign what the agent is
about to do. The sidecar holds the signing key. This process never sees it.

Start the sidecar before the agent:

    vouch sidecar --did @@DID@@ --allowlist vouch-allowlist.json
"""
import json
from typing import Any, Callable, Dict, Optional

import httpx

SIDECAR_URL = "http://127.0.0.1:8877/sign"
ISSUER_DID = @@DID_LITERAL@@


def vouch_headers(
    action: str, target: str, resource: str, valid_seconds: Optional[int] = None
) -> Dict[str, str]:
    """Ask the sidecar to sign one action and return the header to send with it.

    `valid_seconds` is how long the signature stays valid. Leave it out to get
    the sidecar's default.
    """
    request: Dict[str, Any] = {
        "intent": {"action": action, "target": target, "resource": resource}
    }
    if valid_seconds is not None:
        request["validSeconds"] = valid_seconds
    response = httpx.post(SIDECAR_URL, json=request, timeout=2.0)
    response.raise_for_status()
    credential = response.json()
    if credential.get("issuer") != ISSUER_DID:
        raise RuntimeError("the sidecar signed as an unexpected issuer")
    return {"Vouch-Token": json.dumps(credential, separators=(",", ":"))}


def vouch_tool(
    action: str, target: str, resource: str, valid_seconds: Optional[int] = None
) -> Callable:
    """Decorator: sign the action, then call the tool with `_vouch_headers` set."""

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            kwargs["_vouch_headers"] = vouch_headers(action, target, resource, valid_seconds)
            return fn(*args, **kwargs)

        return wrapped

    return decorator


# Example. This signature is good for two minutes:
# @vouch_tool(
#     "http.post",
#     target="partner-api",
#     resource="https://api.partner.example/orders",
#     valid_seconds=120,
# )
# def send_to_partner(body: dict, _vouch_headers=None):
#     return httpx.post("https://api.partner.example/orders", json=body, headers=_vouch_headers)
''',
    "typescript": """/**
 * Vouch Protocol tool-call wrapper.
 *
 * Wrap a tool so that every call first asks the sidecar to sign what the agent
 * is about to do. The sidecar holds the signing key. This process never sees it.
 *
 * Start the sidecar before the agent:
 *
 *   vouch sidecar --did @@DID@@ --allowlist vouch-allowlist.json
 */
const SIDECAR_URL = "http://127.0.0.1:8877/sign";
const ISSUER_DID = @@DID_LITERAL@@;

export interface Intent {
  action: string;
  target: string;
  resource: string;
}

export type VouchHeaders = Record<string, string>;

/**
 * Ask the sidecar to sign one action and return the header to send with it.
 * `validSeconds` is how long the signature stays valid. Leave it out to get the
 * sidecar's default.
 */
export async function vouchHeaders(intent: Intent, validSeconds?: number): Promise<VouchHeaders> {
  const res = await fetch(SIDECAR_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(validSeconds === undefined ? { intent } : { intent, validSeconds }),
  });
  if (!res.ok) throw new Error(`Vouch Protocol sidecar /sign failed: ${res.status}`);
  const credential = await res.json();
  if (credential.issuer !== ISSUER_DID) {
    throw new Error("the sidecar signed as an unexpected issuer");
  }
  // Header values must be ASCII, so escape anything else.
  const token = JSON.stringify(credential).replace(
    /[\\u007f-\\uffff]/g,
    (c) => "\\\\u" + c.charCodeAt(0).toString(16).padStart(4, "0"),
  );
  return { "Vouch-Token": token };
}

/** Wrap a tool so each call is signed first. The tool gets the headers as its last argument. */
export function vouchTool<A extends unknown[], R>(
  intent: Intent,
  fn: (...args: [...A, VouchHeaders]) => R | Promise<R>,
  validSeconds?: number,
): (...args: A) => Promise<R> {
  return async (...args: A) => fn(...args, await vouchHeaders(intent, validSeconds));
}

// Example:
// const sendToPartner = vouchTool(
//   { action: "http.post", target: "partner-api", resource: "https://api.partner.example/orders" },
//   (body: unknown, headers: VouchHeaders) =>
//     fetch("https://api.partner.example/orders", {
//       method: "POST",
//       headers: { ...headers, "content-type": "application/json" },
//       body: JSON.stringify(body),
//     }),
// );
""",
    "go": """// Vouch Protocol tool-call wrapper.
//
// Call VouchSign before a tool runs to ask the sidecar to sign what the agent
// is about to do. The sidecar holds the signing key. This process never sees it.
//
// Start the sidecar before the agent:
//
//	vouch sidecar --did @@DID@@ --allowlist vouch-allowlist.json
package vouchwire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf16"
)

const (
	SidecarURL = "http://127.0.0.1:8877/sign"
	IssuerDID  = @@DID_LITERAL@@
)

// Intent is the action the agent is about to take.
type Intent struct {
	Action   string `json:"action"`
	Target   string `json:"target"`
	Resource string `json:"resource"`
}

var client = &http.Client{Timeout: 2 * time.Second}

type signRequest struct {
	Intent       Intent `json:"intent"`
	ValidSeconds int    `json:"validSeconds,omitempty"`
}

// VouchSign asks the sidecar to sign intent. Send the returned string as the
// Vouch-Token header of the call the tool makes.
//
// validFor is how long the signature stays valid. Pass 0 to get the sidecar's
// default.
func VouchSign(intent Intent, validFor time.Duration) (string, error) {
	body, err := json.Marshal(signRequest{Intent: intent, ValidSeconds: int(validFor / time.Second)})
	if err != nil {
		return "", err
	}
	resp, err := client.Post(SidecarURL, "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vouch sidecar /sign: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var credential struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(raw, &credential); err != nil {
		return "", err
	}
	if credential.Issuer != IssuerDID {
		return "", errors.New("the sidecar signed as an unexpected issuer")
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return "", err
	}
	return asciiJSON(compact.String()), nil
}

// asciiJSON escapes non-ASCII characters so the JSON is a valid header value.
func asciiJSON(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 0x7f:
			b.WriteRune(r)
		case r > 0xffff:
			hi, lo := utf16.EncodeRune(r)
			fmt.Fprintf(&b, "\\\\u%04x\\\\u%04x", hi, lo)
		default:
			fmt.Fprintf(&b, "\\\\u%04x", r)
		}
	}
	return b.String()
}

// Example:
//
//	token, err := vouchwire.VouchSign(vouchwire.Intent{
//		Action:   "http.post",
//		Target:   "partner-api",
//		Resource: "https://api.partner.example/orders",
//	}, 2*time.Minute)
//	req.Header.Set("Vouch-Token", token)
""",
}


_VERIFIER_SNIPPETS = {
    "python": '''"""Vouch Protocol verifier for FastAPI.

Add `Depends(require_vouch)` to every route an agent can call. For each request
it checks the credential in the Vouch-Token header: that it was signed with your
issuer's key, that it is inside its validity window, and that the signed action
is on your allow-list. A request that fails any check never reaches your code.

    pip install vouch-protocol fastapi
"""
import json
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException

from vouch.integrations.fastapi import VouchGate

ISSUER_DID = @@DID_LITERAL@@
# The issuer's public key. Only credentials signed with its private half pass.
ISSUER_PUBLIC_KEY = @@PUBLIC_KEY_JWK_LITERAL@@
ALLOWLIST = json.loads(Path(@@ALLOWLIST_LITERAL@@).read_text())
ALLOWED_ACTIONS = {a["name"] for a in ALLOWLIST["actions"]}

gate = VouchGate(header="Vouch-Token", trusted_keys={ISSUER_DID: ISSUER_PUBLIC_KEY})


async def require_vouch(passport=Depends(gate)):
    """Reject a verified credential whose action is not on the allow-list."""
    if passport.action not in ALLOWED_ACTIONS:
        raise HTTPException(403, f"Action {passport.action!r} is not on the allow-list")
    return passport


app = FastAPI()


@app.post("/example")
async def example(passport=Depends(require_vouch)):
    return {"agent": passport.iss, "action": passport.action}
''',
    "typescript": """/**
 * Vouch Protocol verifier middleware for Express.
 *
 * For each request it checks the credential in the Vouch-Token header: that it
 * was signed with your issuer's key, that it is inside its validity window, and
 * that the signed action is on your allow-list. A request that fails any check
 * never reaches your routes.
 *
 *   npm install @vouch-protocol-official/sdk
 */
import { readFileSync } from "node:fs";
import type { Request, Response, NextFunction } from "express";
import { verify } from "@vouch-protocol-official/sdk";

const ISSUER_DID = @@DID_LITERAL@@;
// The issuer's public key. Only credentials signed with its private half pass.
const ISSUER_PUBLIC_KEY = @@PUBLIC_KEY_JWK_OBJECT@@;
const ALLOWLIST = JSON.parse(readFileSync(@@ALLOWLIST_LITERAL@@, "utf-8"));
const ALLOWED = new Set<string>(ALLOWLIST.actions.map((a: { name: string }) => a.name));

export async function vouchMiddleware(req: Request, res: Response, next: NextFunction) {
  const token = req.header("Vouch-Token");
  if (!token) return res.status(401).send("Missing Vouch-Token");

  let passport;
  try {
    const result = await verify(token, ISSUER_PUBLIC_KEY);
    passport = result.isValid ? result.passport : null;
  } catch {
    passport = null;
  }
  if (!passport || passport.iss !== ISSUER_DID) {
    return res.status(401).send("Invalid Vouch-Token");
  }
  if (!ALLOWED.has(passport.intent.action)) {
    return res.status(403).send("Action is not on the allow-list");
  }
  (req as Request & { vouchPassport?: unknown }).vouchPassport = passport;
  next();
}
""",
    "go": """// Vouch Protocol verifier middleware for net/http.
//
// For each request it checks the credential in the Vouch-Token header: that it
// was signed with your issuer's key, that it is inside its validity window, and
// that the signed action is on your allow-list. A request that fails any check
// never reaches your handler.
//
//	go get github.com/vouch-protocol/vouch/go-sidecar
package vouchverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	"github.com/vouch-protocol/vouch/go-sidecar/signer"
)

const (
	IssuerDID = @@DID_LITERAL@@
	// The issuer's public key. Only credentials signed with its private half pass.
	IssuerPublicKey = @@PUBLIC_KEY_MULTIKEY_LITERAL@@
	allowlistPath   = @@ALLOWLIST_LITERAL@@
)

type passportKey struct{}

// PassportFrom returns the verified credential of a request that passed Middleware.
func PassportFrom(r *http.Request) *signer.CredentialPassport {
	passport, _ := r.Context().Value(passportKey{}).(*signer.CredentialPassport)
	return passport
}

// Middleware rejects every request that does not carry a valid credential for
// an allow-listed action. It returns an error if the issuer key or the
// allow-list cannot be loaded, so a broken setup never lets requests through.
func Middleware(next http.Handler) (http.Handler, error) {
	algorithm, issuerKey, err := signer.MultikeyDecode(IssuerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("issuer public key: %w", err)
	}
	if algorithm != "Ed25519" {
		return nil, errors.New("issuer public key must be an Ed25519 key")
	}
	allowed, err := loadAllowed(allowlistPath)
	if err != nil {
		return nil, err
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Vouch-Token")
		if token == "" {
			http.Error(w, "missing Vouch-Token", http.StatusUnauthorized)
			return
		}
		var credential map[string]any
		if err := json.Unmarshal([]byte(token), &credential); err != nil {
			http.Error(w, "invalid Vouch-Token", http.StatusUnauthorized)
			return
		}
		ok, passport, err := signer.Verify(credential, issuerKey, 30)
		if err != nil || !ok || passport == nil || passport.Issuer != IssuerDID {
			http.Error(w, "invalid Vouch-Token", http.StatusUnauthorized)
			return
		}
		if !allowed[passport.Action()] {
			http.Error(w, "action is not on the allow-list", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), passportKey{}, passport)
		next.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}

func loadAllowed(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("allow-list: %w", err)
	}
	var doc struct {
		Actions []struct {
			Name string `json:"name"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("allow-list: %w", err)
	}
	allowed := map[string]bool{}
	for _, action := range doc.Actions {
		if action.Name != "" {
			allowed[action.Name] = true
		}
	}
	if len(allowed) == 0 {
		return nil, errors.New("allow-list names no actions")
	}
	return allowed, nil
}
""",
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
    io.out("Next:")
    io.out(f"  1. Publish did.json at https://{state.domain}/.well-known/did.json")
    io.out("  2. Start the sidecar next to your agent:")
    io.out(f"       {_sidecar_command(state)}")
    io.out("  3. Wrap your tools with the tool wrapper and add the verifier to your API.")


def _sidecar_command(state: OnboardState) -> str:
    """The command that starts the sidecar with this run's identity and allow-list.

    The sidecar finds the identity's key in the keystore by its DID, so there
    is no key to pass.
    """
    allowlist = state.allowlist_path or "vouch-allowlist.json"
    return f'vouch sidecar --did {state.did} --allowlist "{allowlist}"'


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
    quick = getattr(args, "quick", False)
    domain_supplied = bool(getattr(args, "domain", None))
    preset: Dict[str, str] = {}
    if domain_supplied:
        preset["domain"] = args.domain
    if getattr(args, "tier", None):
        preset["tier"] = args.tier
    if getattr(args, "lang", None):
        preset["toolwire_lang"] = args.lang
        preset["verifier_lang"] = args.lang

    # Quick mode: run start-to-finish with no questions. Every other field
    # already has a recommended default; domain is the only one that does not,
    # so seed a placeholder the summary tells the user to replace.
    if quick and not domain_supplied:
        preset.setdefault("domain", "agent.example")

    try:
        rc = run_wizard(
            resume=getattr(args, "resume", False),
            # Quick mode always starts fresh so re-running it just works instead of
            # short-circuiting on a prior completed run.
            reset=getattr(args, "reset", False) or quick,
            interactive=not (getattr(args, "non_interactive", False) or quick),
            dry_run=getattr(args, "dry_run", False),
            out_dir=getattr(args, "out_dir", ".") or ".",
            preset_answers=preset,
        )
    except (ValueError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    if rc == 0 and quick and not domain_supplied:
        print(
            "\nNote: used the placeholder domain 'agent.example'. "
            "Re-run with --domain your.domain to bind the identity to a real host."
        )
    return rc
