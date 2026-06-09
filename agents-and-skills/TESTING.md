# Testing Steps for All Four Packages

Manual verification steps for each deliverable. Everything below
assumes you are inside `~/vouch-protocol/` on Linux/WSL/macOS.

---

## 1. Claude Skill (`claude-skill/`)

### Install locally

```bash
mkdir -p ~/.claude/skills
cp -r claude-skill ~/.claude/skills/vouch-protocol
```

### Verify Claude Code picks it up

In a Claude Code session:

```
/skills
```

Expect to see `vouch-protocol` in the list.

### Functional tests (run each in a fresh Claude Code session)

Each prompt should make Claude open the named reference file and
produce protocol-correct output.

| Prompt | Expected file | Expected behavior |
|---|---|---|
| "Show me a Python quickstart for signing a Vouch credential." | `reference/python-sdk.md` | Code with `generate_identity`, `Signer(private_key=..., did=...)`, `build_vouch_credential`, `sign_credential`, `Verifier.verify_credential` |
| "Enable the hybrid post-quantum signature for my agent." | `reference/post-quantum.md` | Code that sets cryptosuite to `hybrid-eddsa-mldsa44-jcs-2026` |
| "Wrap a LangChain tool with Vouch." | `reference/integrations.md` | `VouchTool` wrapper code with `intent_template` |
| "Why is my verifier returning verificationMethod_not_found?" | `reference/troubleshooting.md` | Three causes (rotation, cache, mismatch) |
| "Build a heartbeat session that decays trust over 60 seconds." | `reference/state-verifiability.md` | `HeartbeatSession` + `HeartbeatScheduler` code |
| "Set up an Identity Sidecar in Docker Compose." | `reference/sidecar.md` | docker-compose.yaml with read-only key mount |

### Pass criteria

- All six prompts trigger a Read of the correct file in `reference/`.
- All produced code uses real SDK method names (no hallucinations).
- Claude cites the source file at the end of each significant claim.

### Fail handling

If Claude does NOT load the skill: check `~/.claude/skills/vouch-protocol/SKILL.md`
exists and starts with a valid YAML frontmatter block.

If the skill loads but Claude does not use it: paste the SKILL.md
contents back into Claude and ask "Why did you not use this skill?"

---

## 2. Website Agent (`website-agent/`)

### Backend smoke test (no LLM key required)

```bash
cd website-agent/backend
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

Expect: all tests in `tests/test_rag.py` and `tests/test_signer.py`
pass.

### Full local run

You need three terminals.

**Terminal 1: Vouch sidecar**

```bash
cd go-sidecar
go run ./cmd/vouch-sidecar --did did:web:agent.vouch-protocol.com --port 8877
```

If you don't have Go installed, use the Python bridge:

```bash
pip install 'vouch-protocol[server]'
vouch-bridge --did did:web:agent.vouch-protocol.com --port 8877
```

**Terminal 2: Agent backend**

```bash
cd website-agent/backend
export ANTHROPIC_API_KEY=sk-ant-...
export VOUCH_SIDECAR_URL=http://localhost:8877
uvicorn vouch_agent.main:app --reload --port 8000
```

**Terminal 3: Smoke checks**

```bash
# Health check
curl -s http://localhost:8000/healthz | jq
# Expect: { "ok": true, "sidecar_ok": true, "knowledge_chunks": > 0 }

# Chat (no signing)
curl -N -X POST http://localhost:8000/chat \
    -H 'content-type: application/json' \
    -d '{"message":"What is the Vouch protocol?"}'
# Expect: SSE stream with event: meta, event: token... , event: done

# Sign an allow-listed intent
curl -s -X POST http://localhost:8000/sign \
    -H 'content-type: application/json' \
    -d '{
        "intent": {
            "action": "answer_question",
            "target": "session:abc",
            "resource": "https://vouch-protocol.com/help"
        }
    }' | jq
# Expect: { "credential": { ... signed VC ... }, "audit": { ... } }

# Reject a disallowed action
curl -s -X POST http://localhost:8000/sign \
    -H 'content-type: application/json' \
    -d '{
        "intent": { "action": "exfiltrate_keys", "target": "x", "resource": "x" }
    }'
# Expect: HTTP 400 with body { "detail": "action 'exfiltrate_keys' not in allow-list" }

# Audit log
curl -s http://localhost:8000/audit | jq
# Expect: at least one entry from the previous sign request
```

### Frontend widget test

In the existing Next.js website:

```bash
cp -r website-agent/frontend/components website/components/vouch-chat
```

Add a temporary test page:

```tsx
// website/app/agent-test/page.tsx
'use client';
import { VouchChat } from '@/components/vouch-chat/VouchChat';
import '@/components/vouch-chat/styles.css';

export default function AgentTest() {
    return (
        <div style={{ height: '80vh', padding: 24 }}>
            <VouchChat apiBase="http://localhost:8000" />
        </div>
    );
}
```

```bash
cd website && npm run dev
# open http://localhost:3000/agent-test
```

Pass criteria:
- Type a question, get a streamed answer.
- Sources appear under the bubble.
- (If sign is invoked) a CredentialCard renders with VOUCH CREDENTIAL badge.
- No console errors.

### Pass criteria summary

- pytest: all green
- `/healthz`: ok=true, sidecar_ok=true
- `/chat`: SSE streams tokens
- `/sign`: returns a valid signed credential for allowed actions; 400 for others
- Frontend: widget renders, chat works, CredentialCard shows when a credential is returned

---

## 3. OpenAI Custom GPT (`openai-gpt/`)

### Build the GPT

1. Open https://chatgpt.com/gpts/editor
2. Click "Create"
3. In Configure tab, paste each field from its file:
    - Name -> `name.txt`
    - Description -> `description.txt`
    - Instructions -> `instructions.md`
    - Conversation starters -> one line per starter from `conversation-starters.md`
4. Upload all files in `knowledge/` to the Knowledge section
5. Capabilities: enable "Web Browsing" and "Code Interpreter"
6. (Optional) Add Actions: paste `actions.yaml`, configure auth per `actions-auth.md`
7. Save as "Only me" for testing first

### Functional tests in the GPT preview pane

Run each:

| Prompt | Expected |
|---|---|
| "Show me a Python quickstart for signing a Vouch credential." | Code from quickstart.md; cites `[knowledge: quickstart.md]` or similar |
| "Compare classical and hybrid PQ cryptosuites." | Mentions `eddsa-jcs-2022` and `hybrid-eddsa-mldsa44-jcs-2026`; cites post-quantum.md |
| "My verifier returns nonce_replay. What does that mean?" | Explanation from troubleshooting.md |
| "How does the canary chain detect silent failures?" | Drawn from state-verifiability.md |

### Actions test (only if you configured Actions)

In the GPT preview, type:

> "Sign a credential for me with action=answer_question target=test-session-1 resource=https://vouch-protocol.com/help"

The GPT should:
1. Summarize the credential it is about to sign.
2. Ask for explicit confirmation.
3. Only after you type "yes", call `signCredential`.
4. Show you the returned credential id and proof fields.

### Pass criteria

- All four functional prompts produce protocol-correct answers grounded in the knowledge files.
- The GPT refuses to invent SDK methods.
- (If Actions are wired) The GPT asks before signing and shows the result.

---

## 4. Gemini Gem (`gemini-gem/`)

### Build the Gem

1. Open https://gemini.google.com/gems/create  (Gemini Advanced / AI Pro required for the full feature set)
2. Click "New Gem"
3. Paste from each file:
    - Name -> `name.txt`
    - Description -> `description.txt`
    - Instructions -> `instructions.md`
4. Upload all files from `knowledge/` (Gemini supports up to ten knowledge files; the corpus is ten files exactly).
5. Optionally add the `examples.md` lines as the Gem's Examples.
6. Click Preview.

### Functional tests in the Gem preview

| Prompt | Expected |
|---|---|
| "Show me a Python quickstart for signing a Vouch credential." | Code with SDK shapes from quickstart.md |
| "How do I rotate a compromised did:web key?" | Steps from revocation.md (DID-level registry) |
| "Draft a Google Doc explaining the agent-identity threat model." | Gem asks for confirmation, then creates the Doc using Workspace tools |
| "Search GitHub for the latest Vouch release." | Gem uses Google Search and reports the version |

### Pass criteria

- Protocol-correct answers in all preview prompts.
- Workspace tools (Docs / Search) used when prompted, with confirmation before creating user data.
- The Gem cites knowledge files for protocol claims.

---

## Cross-package consistency check

Run the same prompt in all four surfaces:

> "What cryptosuite identifier do I use for the hybrid post-quantum profile?"

Expected answer (verbatim string somewhere in the response): `hybrid-eddsa-mldsa44-jcs-2026`

If any surface produces a different string, that surface's knowledge or instructions need fixing.

---

## Reporting issues

For each failure, capture:

1. Which package (claude-skill / website-agent / openai-gpt / gemini-gem)
2. The exact prompt
3. The actual response (paste)
4. The expected behavior

File issues at https://github.com/vouch-protocol/vouch/issues with tag
matching the package name.
