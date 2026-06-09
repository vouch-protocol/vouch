# Vouch Website Agent: production deployment

End-to-end runbook to bring the assistant from local-only to
`https://agent.vouch-protocol.com` and flip the panel on
`vouch-protocol.com` from "coming soon" to live.

Single Fly.io app, single container, two processes inside:
**Go sidecar** (holds the Ed25519 key, signs intents) and
**FastAPI backend** (RAG + Gemini, talks to the sidecar over
`127.0.0.1:8877`). The sidecar is never reachable from the public
internet.

```
visitor browser
       │
       ▼  HTTPS, edge TLS at Fly
agent.vouch-protocol.com
       │
       ▼  internal_port 8000
┌───────────────────────────┐
│  uvicorn  /chat /healthz  │
│           /.well-known/…  │
│        ▲                  │
│        │ 127.0.0.1:8877   │
│        ▼                  │
│  vouch-sidecar (Go)       │
│  Ed25519 seed from env    │
└───────────────────────────┘
```

---

## One-time setup (≈ 30 min, do once ever)

### 1. Generate the production keypair

The script is at `website-agent/deploy/keygen.py`. It writes a
32-byte Ed25519 seed, the public Multikey, and the DID document into a
directory you choose.

```bash
cd ~/vouch-protocol
source ~/miniconda3/etc/profile.d/conda.sh && conda activate vouch-agent
python website-agent/deploy/keygen.py \
    --did did:web:agent.vouch-protocol.com \
    --out ~/.vouch/agent-prod
```

Output:
```
~/.vouch/agent-prod/seed.hex         (mode 0600, NEVER commit, NEVER paste in chat)
~/.vouch/agent-prod/public.multikey  (public, fine to share)
~/.vouch/agent-prod/did.json         (public, served at /.well-known/did.json)
~/.vouch/agent-prod/GENERATED        (timestamp marker)
```

Copy the DID document into the image build context:
```bash
cp ~/.vouch/agent-prod/did.json website-agent/deploy/did.json
```

Back up `seed.hex` somewhere safe (1Password / Bitwarden / hardware
token). If you lose it the agent's identity is gone and every
credential it has ever signed is unverifiable.

### 2. Install flyctl

```bash
curl -L https://fly.io/install.sh | sh
echo 'export FLYCTL_INSTALL="$HOME/.fly"' >> ~/.vouch/env
echo 'export PATH="$FLYCTL_INSTALL/bin:$PATH"' >> ~/.vouch/env
. ~/.vouch/env
fly version
```

### 3. Fly login + app create

```bash
fly auth login                         # opens browser, OAuth
cd ~/vouch-protocol
fly apps create vouch-agent --org personal     # rename --org if you have one
```

### 4. Set Fly secrets

```bash
fly secrets set --app vouch-agent \
    GEMINI_API_KEY="$(grep ^GEMINI_API_KEY ~/vouch-protocol/website-agent/.env | cut -d= -f2-)" \
    VOUCH_ED25519_SEED="$(cat ~/.vouch/agent-prod/seed.hex)"
```

Verify (the values are masked):
```bash
fly secrets list --app vouch-agent
```

### 5. First deploy

```bash
cd ~/vouch-protocol
fly deploy --app vouch-agent --config website-agent/deploy/fly.toml --dockerfile website-agent/deploy/Dockerfile
```

This takes ~3-5 minutes the first time (Go build + Python install).
When it lands, sanity-check:

```bash
curl -fsS https://vouch-agent.fly.dev/healthz
# {"ok":true,"sidecar_ok":true,"knowledge_chunks":99}

curl -fsS https://vouch-agent.fly.dev/.well-known/did.json | head
# {"@context":["https://www.w3.org/ns/did/v1", …
```

### 6. Custom domain (`agent.vouch-protocol.com`)

In Cloudflare DNS for `vouch-protocol.com`, add:
```
Type   Name    Content                 Proxy
CNAME  agent   vouch-agent.fly.dev     DNS only (grey cloud)
```

Then ask Fly to issue a cert:
```bash
fly certs add --app vouch-agent agent.vouch-protocol.com
fly certs show --app vouch-agent agent.vouch-protocol.com
```

Wait until it shows `Status = Ready` (usually under 60 seconds).
Verify the cert end-to-end:
```bash
curl -fsS https://agent.vouch-protocol.com/healthz
curl -fsS https://agent.vouch-protocol.com/.well-known/did.json
```

You can flip Cloudflare proxy to orange-cloud later if you want CDN +
DDoS in front of Fly. Leave it grey for the initial issuance.

### 7. Wire the website panel

The build workflow `.github/workflows/deploy-website.yml` already reads
the env var `NEXT_PUBLIC_VOUCH_AGENT_URL` from a GitHub Actions
repository variable named `VOUCH_AGENT_URL`. Set it:

GitHub: **Settings → Secrets and variables → Actions → Variables → New**
```
Name:  VOUCH_AGENT_URL
Value: https://agent.vouch-protocol.com
```

Then trigger a rebuild of the website (any commit under `website/`,
or `workflow_dispatch` from the Actions tab). When the new static
export ships, `AgentPanel.tsx` switches from `<ComingSoonBody />` to
`<AgentChat apiBase="https://agent.vouch-protocol.com">`.

### 8. End-to-end smoke test on production

```bash
# 1. Backend reachable, sidecar reachable
curl -fsS https://agent.vouch-protocol.com/healthz

# 2. DID document resolves (needed for any verifier to check signatures)
curl -fsS https://agent.vouch-protocol.com/.well-known/did.json | jq .id

# 3. Chat streams
curl -N -X POST https://agent.vouch-protocol.com/chat \
    -H "Content-Type: application/json" \
    -d '{"message":"What is the Identity Sidecar pattern?"}'

# 4. Sign-and-act path (a real credential gets emitted)
curl -fsS -X POST https://agent.vouch-protocol.com/sign \
    -H "Content-Type: application/json" \
    -d '{"intent":{"action":"echo","target":"self","resource":"urn:vouch:smoke-test"}}'

# 5. Open https://vouch-protocol.com, click "Ask the assistant", run the
#    four prompts from notes/release-checklist-2026-05-14.md §F.1.
```

---

## Day-to-day deploys

After the initial setup, a normal redeploy is one command:
```bash
cd ~/vouch-protocol
fly deploy --app vouch-agent \
    --config website-agent/deploy/fly.toml \
    --dockerfile website-agent/deploy/Dockerfile
```

Knowledge corpus edits in `website-agent/backend/knowledge/` ship as
part of the image (the `.index` is rebuilt on container boot from the
files in the image).

---

## Cost expectations

- Fly.io shared-cpu-1x / 512 MB: free tier covers low traffic
  (auto-stop machines when idle, < 3 hr/day of active CPU).
- Cloudflare DNS + cert: free.
- Gemini API: pay-per-token; with `gemini-2.5-flash` and current
  pricing, ~$0.0001 per chat. A thousand visitor chats per day costs
  about $3/month.
- Total expected: $0-5/month at incubation traffic.

---

## Rotating the agent identity

If `seed.hex` ever leaks, rotate immediately:

```bash
python website-agent/deploy/keygen.py \
    --did did:web:agent.vouch-protocol.com \
    --out ~/.vouch/agent-prod-2026-xx \
    # NOTE: new directory each time, so the old one is preserved for forensics

cp ~/.vouch/agent-prod-2026-xx/did.json website-agent/deploy/did.json
fly secrets set --app vouch-agent VOUCH_ED25519_SEED="$(cat ~/.vouch/agent-prod-2026-xx/seed.hex)"
fly deploy --app vouch-agent --config website-agent/deploy/fly.toml --dockerfile website-agent/deploy/Dockerfile
```

Every credential issued under the old key is now unverifiable (which is
the point of rotation after a compromise). Record the rotation in the
audit log.

---

## Why one container, not two

Fly does support multi-process apps and multi-app deployments. We use
one container with the two-process supervisor (`start.sh`) because:

- The sidecar is intentionally not exposed to the public internet.
  Co-locating it with the FastAPI process keeps it on `127.0.0.1` and
  eliminates an entire class of cross-app auth bugs.
- Cold-start latency is one warm-up, not two.
- Logs interleave naturally for debugging.

The container exits if either process dies, and Fly restarts it. That
fail-fast behaviour is preferable to a half-up agent serving 503s.
