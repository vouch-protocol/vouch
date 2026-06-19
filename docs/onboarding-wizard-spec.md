# Vouch Onboarding Wizard: Specification

Status: design, v1
Last updated: 2026-05-18
Owner: Vouch Protocol editor

## 1. Purpose

The Vouch Protocol paper, section 12.2 (Adoption Path), describes a six-step path
that a new deployment follows to put Vouch in front of a production agent. The
prose target is "1–2 engineering days for the credential layer, 2–4 days for state
verifiability and quorum."

In practice every team that has gone through this path has rebuilt the same six
artifacts by hand: an issuer DID Document, a sidecar config, an allow-list, a
tool-call wrapper, a verifier middleware, and a heartbeat validator. The
wizard's job is to collapse that day-of-work into roughly thirty interactive
minutes by generating every artifact for you, persisting progress, and letting
you resume across machines.

There are three surfaces, all driven by the same underlying step model:

1. **CLI wizard** (`vouch onboard`) that does the work and writes artifacts to
   disk. This is the canonical surface; engineers will run it during a
   deployment.
2. **Website stepper** (`/onboard` on vouch-protocol.com) that teaches the same
   six steps with copy-paste commands and inline preview of the artifacts the
   CLI would produce. This is the "look-before-you-leap" surface for evaluators
   and procurement.
3. **Specification** (this document) that fixes the step contract so both
   surfaces stay in lockstep.

## 2. Step model

The wizard is a finite state machine over six steps. Each step has a stable
slug, a precondition, a side effect, and a persisted artifact. Steps must be
completed in order, but `--resume` re-enters at the first incomplete step.

| # | Slug          | Side effect                                            | Artifact                                  |
|---|---------------|--------------------------------------------------------|-------------------------------------------|
| 1 | `identity`    | Generate Ed25519 keypair, derive did:web DID           | `~/.vouch/keys/<did>.json`, `did.json`    |
| 2 | `tier`        | Pick Sidecar tier (Edge / Standard / Regulated)        | `~/.vouch/onboarding.json` (tier field)   |
| 3 | `allowlist`   | Pick action vocabulary from a starter set or paste own | `./vouch-allowlist.json`                  |
| 4 | `toolwire`    | Emit framework-specific wrapper for the agent runtime  | `./vouch-toolwire.<py\|ts\|go>`           |
| 5 | `verifier`    | Emit middleware snippet for the API boundary           | `./vouch-verifier.<py\|ts\|go>`           |
| 6 | `heartbeat`   | Emit heartbeat validator deployment manifest           | `./vouch-heartbeat.yaml` (or `.json`)     |

Step 6 is conditional: skipped for short-lived agents, required (with quorum
of three) for regulated tier.

### 2.1 Step contract

Every step implements the same Python contract:

```python
class OnboardStep(Protocol):
    slug: str
    title: str
    blurb: str

    def is_complete(self, state: OnboardState) -> bool: ...
    def run(self, state: OnboardState, io: WizardIO) -> StepResult: ...
```

`StepResult` is one of `Done`, `Skipped(reason)`, or `Failed(error)`. The
engine writes the state file after every step transition so an interrupted
session resumes at the same point.

### 2.2 Persisted state

`~/.vouch/onboarding.json` shape:

```json
{
  "version": 1,
  "started_at": "2026-05-18T11:20:00Z",
  "completed_at": null,
  "domain": "agent.acme.example",
  "did": "did:web:agent.acme.example",
  "tier": "standard",
  "allowlist_path": "./vouch-allowlist.json",
  "toolwire_lang": "python",
  "verifier_lang": "python",
  "heartbeat_quorum": 1,
  "steps": {
    "identity":  { "status": "done", "completed_at": "..." },
    "tier":      { "status": "done", "completed_at": "..." },
    "allowlist": { "status": "done", "completed_at": "..." },
    "toolwire":  { "status": "done", "completed_at": "..." },
    "verifier":  { "status": "pending" },
    "heartbeat": { "status": "pending" }
  }
}
```

`--reset` deletes this file. `--resume` (default if the file exists) re-enters
at the first non-`done` step.

## 3. CLI surface

```
vouch onboard [--resume | --reset]
              [--non-interactive]
              [--domain DOMAIN]
              [--tier {edge,standard,regulated}]
              [--lang {python,typescript,go}]
              [--dry-run]
              [--out-dir DIR]
```

Flags:

- `--non-interactive`: never prompt; require every input via flags or env.
  Suitable for CI scaffolding.
- `--dry-run`: print every artifact to stdout, write nothing to disk. Used by
  the website preview pane and by the smoke test.
- `--out-dir`: directory to write `vouch-*.{json,py,ts,go,yaml}` artifacts
  (default: current directory).

Output style follows existing CLI conventions in `vouch/cli.py`: section
headers with a leading emoji, then plain text. (The codebase already uses
this style; the wizard matches it for visual consistency.)

## 4. Website surface

Route: `/onboard` on vouch-protocol.com.

The page mirrors the CLI step model exactly. Each step has:

- A short blurb (what this step does and why).
- The exact CLI command that performs it.
- A preview of the artifact the CLI would produce (rendered from a static
  dry-run snapshot built at build time).
- A "Next step" button that advances the local stepper; progress is held in
  `useState`, not in cookies, so nothing is persisted server-side.

The page is purely educational; it does not call any API. Engineers reading
the page should leave with two things: confidence that the six steps are
tractable, and the exact commands to run on their own machine.

## 5. Output artifacts

### 5.1 DID Document (`did.json`)

Standards-aligned did:web document with a single Ed25519 verification method
matching the generated key. The wizard prints the publish path:
`https://<domain>/.well-known/did.json`.

### 5.2 Allow-list

JSON document with an `actions` array. Each action has `name`, `description`,
`scope` (resource pattern), and optional `requires` (delegation depth, etc.).
The wizard ships three starter vocabularies: `read-only`, `read-write-scoped`,
and `regulated`. Users can paste their own action vocabulary in step 3.

### 5.3 Tool-call wrapper

Framework wrapper that intercepts agent tool calls, looks them up against the
allow-list, and calls the Sidecar's `/sign` endpoint to mint a credential
before the underlying tool runs. The wizard generates one of:

- Python (LangChain, CrewAI, AutoGen, Vertex, ADK, MCP)
- TypeScript (raw, n8n, LangChain.js)
- Go (raw http client)

Detection of which framework is in use is best-effort; the wizard asks if it
cannot guess.

### 5.4 Verifier middleware

Drop-in middleware for the API boundary that calls `Verifier.verify` on the
incoming `Vouch-Token` header and rejects requests whose action is not in the
allow-list. One snippet per major web framework (FastAPI, Express, Gin).

### 5.5 Heartbeat manifest

Docker Compose or Kubernetes manifest that stands up one (or three, for
regulated tier) heartbeat validators pointing at the issuer DID. Includes a
sample policy that flags sessions whose action rate exceeds a threshold.

## 6. Non-goals

- The wizard does not deploy infrastructure. It generates artifacts and prints
  the commands you would run; the operator runs them.
- The wizard does not push DID Documents to your domain. The operator commits
  the generated `did.json` to their web server's `.well-known/` directory.
- The wizard does not configure cloud KMS. Step 1 generates a software key by
  default; the printed next-step guidance points at the KMS integration docs
  for production migration.

## 7. Success criteria

- A first-time user, with no prior Vouch exposure, can run `vouch onboard` and
  reach a deployable artifact set in under thirty minutes on a clean machine.
- The same user can read `/onboard` on the website in under five minutes and
  decide whether to invest those thirty minutes.
- Resuming after interruption works correctly across both Linux and macOS;
  re-running a completed step is idempotent.
- The CLI dry-run output and the website preview pane are byte-identical for
  the same inputs, enforced by a snapshot test in `tests/test_onboard.py`.
