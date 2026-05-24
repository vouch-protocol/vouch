/**
 * Six-step adoption path from the Vouch Protocol paper, section 12.2.
 *
 * This data drives the /onboard stepper page. Each step mirrors a step in
 * the `vouch onboard` CLI wizard (see vouch/onboard.py and
 * docs/onboarding-wizard-spec.md). The command shown is the literal CLI
 * invocation; the preview is a snapshot of the artifact the wizard would
 * write at that step for a representative input.
 */

export interface OnboardStep {
  /** URL anchor and stepper id. */
  id: string;
  /** Step number (1 to 6). */
  num: number;
  /** Short heading shown in the stepper rail. */
  short: string;
  /** Full title shown on the step page. */
  title: string;
  /** One-paragraph explanation of what this step does and why. */
  blurb: string;
  /** Exact shell invocation that performs this step. */
  command: string;
  /** Filename the wizard writes for this step (relative to out-dir). */
  artifact: string;
  /** Language hint for the preview code block. */
  previewLanguage: string;
  /** Preview of the artifact the wizard would write. */
  preview: string;
  /** Estimated time to complete this step. */
  eta: string;
}

export const ONBOARD_STEPS: OnboardStep[] = [
  {
    id: 'identity',
    num: 1,
    short: 'Identity',
    title: 'Generate the issuer DID',
    blurb:
      'The wizard generates an Ed25519 keypair, derives a did:web identifier from your domain, and writes a standards-aligned DID Document. You publish the document at /.well-known/did.json on the domain you chose; everything downstream resolves the issuer through that path.',
    command:
      'vouch onboard --domain agent.acme.example --tier standard --lang python',
    artifact: 'did.json',
    previewLanguage: 'json',
    preview: `{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/jws-2020/v1"
  ],
  "id": "did:web:agent.acme.example",
  "verificationMethod": [
    {
      "id": "did:web:agent.acme.example#key-1",
      "type": "JsonWebKey2020",
      "controller": "did:web:agent.acme.example",
      "publicKeyJwk": {
        "kty": "OKP",
        "crv": "Ed25519",
        "x": "<base64url public key>"
      }
    }
  ],
  "authentication": ["did:web:agent.acme.example#key-1"],
  "assertionMethod": ["did:web:agent.acme.example#key-1"]
}`,
    eta: '2 minutes',
  },
  {
    id: 'tier',
    num: 2,
    short: 'Tier',
    title: 'Choose a Sidecar tier',
    blurb:
      'Edge runs the signer in-process for the lowest latency; Standard runs a colocated sidecar with KMS-backed keys for multi-agent deployments; Regulated runs the sidecar in a separate VPC with HSM-backed keys and a mandatory heartbeat quorum of three. The wizard records your choice and adjusts later steps to match.',
    command: '# answered inline; the wizard will prompt',
    artifact: '~/.vouch/onboarding.json (tier field)',
    previewLanguage: 'json',
    preview: `{
  "version": 1,
  "domain": "agent.acme.example",
  "did": "did:web:agent.acme.example",
  "tier": "standard",
  "steps": {
    "identity": { "status": "done" },
    "tier":     { "status": "done" }
  }
}`,
    eta: '1 minute',
  },
  {
    id: 'allowlist',
    num: 3,
    short: 'Allow-list',
    title: 'Define the action vocabulary',
    blurb:
      'Every action your agent is permitted to take needs a name, a description, and a resource scope. The wizard ships three starter vocabularies (read-only, read-write-scoped, regulated) and lets you paste your own. The verifier in step 5 will reject any credential whose action is not in this list.',
    command: '# pick a preset interactively',
    artifact: 'vouch-allowlist.json',
    previewLanguage: 'json',
    preview: `{
  "version": 1,
  "issuer": "did:web:agent.acme.example",
  "tier": "standard",
  "actions": [
    {
      "name": "search.web",
      "description": "Read-only web search",
      "scope": "https://*"
    },
    {
      "name": "read.file",
      "description": "Read a local file",
      "scope": "fs:read:./**"
    },
    {
      "name": "write.file",
      "description": "Write to an allow-listed directory",
      "scope": "fs:write:./out/**",
      "requires": { "max_delegation_depth": 1 }
    },
    {
      "name": "http.post",
      "description": "POST to a known partner API",
      "scope": "https://api.partner.example/**",
      "requires": { "max_delegation_depth": 0 }
    }
  ]
}`,
    eta: '5 minutes',
  },
  {
    id: 'toolwire',
    num: 4,
    short: 'Wire tools',
    title: 'Wire the agent tool-call layer to /sign',
    blurb:
      'The wizard generates a thin wrapper for your agent runtime. Every time the agent invokes a tool, the wrapper first calls the Sidecar /sign endpoint to mint a credential bound to that action; the verifier in step 5 will require the credential. The example below is Python; pass --lang typescript or --lang go for the other reference SDKs. Note: this preview uses the legacy v0.x Vouch-Token header path; the v1.0 path issues a Verifiable Credential (content-type application/vouch+credential+json) via sign_credential().',
    command: 'vouch onboard --resume --lang python',
    artifact: 'vouch-toolwire.py',
    previewLanguage: 'python',
    preview: `import httpx
from typing import Any, Callable, Dict

SIDECAR_URL = "http://localhost:8787/sign"
ISSUER_DID = "did:web:agent.acme.example"


def vouch_tool(action: str) -> Callable:
    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        def wrapped(*args: Any, **kwargs: Dict[str, Any]) -> Any:
            r = httpx.post(SIDECAR_URL, json={
                "issuer": ISSUER_DID,
                "action": action,
                "args": kwargs,
            }, timeout=2.0)
            r.raise_for_status()
            token = r.json()["token"]
            kwargs.setdefault("_vouch_headers", {})
            kwargs["_vouch_headers"]["Vouch-Token"] = token
            return fn(*args, **kwargs)
        return wrapped
    return decorator


# @vouch_tool("http.post")
# def send_to_partner(url: str, body: dict, _vouch_headers=None): ...`,
    eta: '10 minutes',
  },
  {
    id: 'verifier',
    num: 5,
    short: 'Verifier',
    title: 'Deploy a verifier at the API boundary',
    blurb:
      'The verifier middleware sits at every endpoint that an agent can call. It checks the Vouch-Token header, validates the signature against the issuer DID, and rejects requests whose action is not in your allow-list. The wizard emits FastAPI, Express, and Gin variants; the FastAPI version is shown below. Note: this preview verifies the legacy v0.x Vouch-Token; for v1.0 Verifiable Credentials use Verifier.verify_credential(credential).',
    command: 'vouch onboard --resume --lang python',
    artifact: 'vouch-verifier.py',
    previewLanguage: 'python',
    preview: `import json
from pathlib import Path
from fastapi import FastAPI, Request, HTTPException
from vouch.verifier import Verifier

ISSUER_DID = "did:web:agent.acme.example"
ALLOWLIST = json.loads(Path("vouch-allowlist.json").read_text())
ALLOWED_ACTIONS = {a["name"] for a in ALLOWLIST["actions"]}

app = FastAPI()


@app.middleware("http")
async def vouch_middleware(request: Request, call_next):
    token = request.headers.get("Vouch-Token")
    if not token:
        raise HTTPException(401, "Missing Vouch-Token header")
    valid, passport = Verifier.verify(token)
    if not valid or not passport:
        raise HTTPException(401, "Invalid Vouch-Token")
    action = (passport.payload or {}).get("action")
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(403, f"Action {action!r} not in allow-list")
    request.state.vouch_passport = passport
    return await call_next(request)`,
    eta: '10 minutes',
  },
  {
    id: 'heartbeat',
    num: 6,
    short: 'Heartbeat',
    title: 'Deploy a heartbeat validator',
    blurb:
      'Long-running agents need a continuous trust signal; the heartbeat validator polls the agent and votes on session health. A single validator is enough for most workloads; the Regulated tier requires a quorum of three, which the wizard sets automatically. Short-lived agents can skip this step.',
    command: 'vouch onboard --resume',
    artifact: 'vouch-heartbeat.yaml',
    previewLanguage: 'yaml',
    preview: `apiVersion: apps/v1
kind: Deployment
metadata:
  name: vouch-heartbeat
spec:
  replicas: 1
  selector:
    matchLabels: { app: vouch-heartbeat }
  template:
    metadata:
      labels: { app: vouch-heartbeat }
    spec:
      containers:
        - name: validator
          image: ghcr.io/vouch-protocol/heartbeat:latest
          env:
            - name: VOUCH_ISSUER_DID
              value: "did:web:agent.acme.example"
            - name: VOUCH_QUORUM
              value: "1"
          ports:
            - containerPort: 8088`,
    eta: '5 minutes',
  },
];
