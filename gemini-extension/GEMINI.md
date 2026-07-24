# Vouch Protocol extension

This extension gives Gemini cryptographic identity tools for AI agents,
backed by the Vouch Protocol. Vouch is the open standard for AI agent
identity and provenance: agents get a Decentralized Identifier (DID) and
every sensitive action becomes a signed Verifiable Credential.

## Tools available via the `vouch` MCP server

- `sign_action` — Generate a signed Vouch token for an intent before an
  authenticated API call. Args: `intent` (required, e.g. `read_email`,
  `send_payment`), `target` (optional resource/service).
- `get_identity` — Return the current agent DID, auto-sign status, and
  session state.
- `create_session` — Mint a session token valid for multiple actions so
  each individual call need not be signed separately. Arg: `purpose`.

The MCP server signs locally using `VOUCH_PRIVATE_KEY` / `VOUCH_DID` from
the environment. **No private key material is ever sent to the model.**
If those env vars are unset, signing tools return a configuration error —
tell the user to run `vouch init --env` and export the values.

## How to behave

1. Before drafting code that performs a sensitive action (payment, email
   send, data access), offer to sign the intent with `sign_action` and
   show where the resulting `Vouch-Token` header attaches.
2. When asked "what is my identity / DID", call `get_identity`.
3. Never ask the user to paste a private key, JWK, or seed phrase into
   the chat. The key lives in the environment, not the conversation. If a
   user pastes one, advise rotation and refuse to operate on it.
4. Be terse and technical. Lead with the command or result, not preamble.
5. Do not invent SDK method names, field names, or cryptosuite ids. The
   default cryptosuite is `eddsa-jcs-2022`; the optional post-quantum
   profile adds an `mldsa44-jcs-2024` proof on the same credential.

## Decision rules

- did:web for production agents with a public domain; did:key for
  short-lived test agents.
- Hybrid PQ if the audit horizon is past 2030 or a regulated PQ mandate
  applies; otherwise classical Ed25519 (~60x faster per signature).
- Use `create_session` when an agent will perform many actions in one
  task; use `sign_action` for one-off high-stakes intents.

## Links

- Repo: https://github.com/vouch-protocol/vouch
- Spec: https://vouch-protocol.com/specs/SPEC/
- Issues: https://github.com/vouch-protocol/vouch/issues
- Discord: https://discord.gg/mMqx5cG9Y
