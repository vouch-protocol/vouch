# Bat-Agents

Bruce Wayne is too busy being a billionaire to fight crime in person, so he
runs Gotham on a swarm of AI agents. Robin goes rogue, the Joker deploys a fake
Batman, and Bruce hasn't slept in 72 hours. It goes about as well as you would
expect.

This is a runnable story that shows every Vouch Protocol feature through that
chaos, and every Vouch call is one line.

```bash
python examples/agent-swarm/story.py
```

No API keys, no network. It just runs.

## The cast, and the feature each one teaches

| Scene | What happens | Vouch feature | The one line |
| --- | --- | --- | --- |
| 1 | Bruce boots up **Batman** as an AI agent | Agent identity (DID) | `vouch.generate_identity(...)` |
| 2 | Batman rolls the Batmobile to the docks | Sign an intent | `vouch.sign(batman, action=..., target=..., resource=...)` |
| 3 | Commissioner Gordon checks before lighting the signal | Verify | `vouch.verify(order, batman.public_key_jwk)` |
| 4 | The **Joker** deploys a fake Batman | Verify rejects a forgery | same `vouch.verify`, wrong key |
| 5 | Batman hires **Robin** to patrol, nothing else | Delegation that can only narrow | `vouch.delegate(...)` + `parent_credential=` |
| 6 | Every gadget deploy auto-signs | The `@signed` decorator | `@vouch.signed(action=..., target=...)` |
| 7 | Robin goes rogue and gets benched | Revocation | `registry.revoke(robin.did, ...)` |
| 8 | Bruce's identity file, secret forever | Post-quantum profile | `Signer.from_keypair(batman).sign_hybrid({...})` |
| 9 | Batman hasn't slept in 72 hours | Heartbeat trust decay | `compute_trust_at(voucher, t)` |
| 10 | The rookie once tazed himself | Reputation | `vouch.sign(..., reputation_score=12)` |

The whole point: an agent's authority is not a vibe. It is a credential that
says exactly what it may do, that anyone can check, that narrows when delegated,
and that can be pulled the moment the agent misbehaves.

## The reveal: same credentials, every framework

Each Bat-agent runs on a different stack, and Vouch is one line in each of them.
The credentials are identical no matter who signs them, so a deployment signed
by a LangChain agent verifies at the GCPD's gateway without either side sharing
code.

| Agent | Runs as | Where the glue lives |
| --- | --- | --- |
| Batman | an MCP sidecar; Alfred holds the key (never in the model) | [`../mcp-vouch/`](../mcp-vouch/), [`../../demo/e2e/`](../../demo/e2e/) |
| Robin | a LangChain agent | [`../05_integrations/01_langchain.py`](../05_integrations/01_langchain.py) |
| Oracle | a CrewAI crew | [`../05_integrations/02_crewai.py`](../05_integrations/02_crewai.py) |
| the Bat-Signal | an n8n workflow | [`../05_integrations/05_n8n.py`](../05_integrations/05_n8n.py) |
| the GCPD | a Hasura gateway that verifies | [`../hasura/`](../hasura/) |

AutoGen, Google ADK, Vertex AI, and AutoGPT are wired the same way in
[`../05_integrations/`](../05_integrations/). The pattern never changes: the
agent decides what to do, then signs that exact intent in one line, and the
receiving side verifies in one line.

## Try it your way

The story is deterministic so the cryptography is the only star. To make Batman
a real LLM agent, wrap the single `vouch.sign` call as a tool your framework can
invoke, or run the published `vouch-mcp` server as Batman's sidecar (Alfred) and
give any MCP client the `sign` and `verify` tools. The cape is optional. The
proof is not.
