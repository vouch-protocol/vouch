# Scene 4 - AAT narrowed offline, enforced by Vouch

A 20-second scene to add to the existing demo. Every command below has been run
as written.

**The line to say on camera:**

> "OAuth-world delegation, narrowed offline; VC-world accountability on top;
> enforced before the call ran."

---

## Before recording

```bash
cd /path/to/vouch-protocol
pip install tenuo
```

Clear any stale demo directory so the scene starts from nothing:

```bash
rm -rf /tmp/aat-demo
```

---

## 1. Show the root AAT

`read_file` **and** `write_file` on `reports/*`.

```bash
python3 integrations/aat/demo_setup.py --out /tmp/aat-demo
```

Expected output:

```
Demo directory: /tmp/aat-demo
  root AAT grants : read_file, write_file on reports/*
  leaf AAT grants : read_file on reports/*
  leaf jti        : tnu_wrt_...
  chain root      : tnu_wrt_...
  leaf depth      : 1

Narrowed offline. No authorization server was contacted.
```

## 2. The narrowing was offline

That single command already did it: the leaf was derived from the root by a
local signing operation, with no authorization-server round trip. To show it is
genuinely disconnected, re-run it with the network off:

```bash
# optional, for the camera
unshare -rn python3 integrations/aat/demo_setup.py --out /tmp/aat-demo-offline
```

Point at the two lines: root grants `read_file, write_file`; leaf grants
`read_file`. The narrowing is the whole scene.

## 3. Start `vouch-mcp` with the leaf

```bash
VOUCH_DID=did:web:demo-agent.example.com \
VOUCH_PRIVATE_KEY="$(cat your-key.jwk)" \
vouch-mcp --aat-chain /tmp/aat-demo/leaf.json \
          --aat-holder-key /tmp/aat-demo/holder.pem
```

For Claude Desktop, use this in `claude_desktop_config.json` instead:

```json
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "args": [
        "--aat-chain", "/tmp/aat-demo/leaf.json",
        "--aat-holder-key", "/tmp/aat-demo/holder.pem"
      ],
      "env": {
        "VOUCH_DID": "did:web:your-agent.example.com",
        "VOUCH_PRIVATE_KEY": "PASTE_YOUR_PRIVATE_KEY_JWK_JSON_STRING",
        "PYTHONPATH": "/path/to/vouch-protocol"
      }
    }
  }
}
```

`PYTHONPATH` matters: the adapter lives in `integrations/`, which is not part of
the installed `vouch` package. Without it the AAT tool fails closed and denies.

## 4. In Claude Desktop: the allowed call

Ask:

> Use the vouch tool `check_action_aat` to check `read_file` with
> `{"path": "reports/q3.txt"}`.

Expected:

```
ALLOW: 'read_file' is permitted by AAT leaf tnu_wrt_... (chain root tnu_wrt_...).
```

To show the credential carrying the AAT `jti`, run in the terminal:

```bash
python3 integrations/aat/demo_call.py \
  --chain /tmp/aat-demo/leaf.json \
  --holder-key /tmp/aat-demo/holder.pem \
  --tool read_file --path reports/q3.txt
```

The frame worth holding is inside `credentialSubject.intent`:

```json
"authorizedBy": {
  "scheme": "aat",
  "jti": "tnu_wrt_...",
  "chainRoot": "tnu_wrt_...",
  "depth": 1
}
```

That is the Vouch credential recording *which delegation authorised this action*.

## 5. The blocked call

`write_file` was in the root and narrowed out of the leaf.

> Use the vouch tool `check_action_aat` to check `write_file` with
> `{"path": "reports/q3.txt"}`.

Expected:

```
DENY: Tool 'write_file' is not in the AAT leaf's authority (leaf permits: read_file)
```

Then in the terminal, to show the tool never ran:

```bash
python3 integrations/aat/demo_call.py \
  --chain /tmp/aat-demo/leaf.json \
  --holder-key /tmp/aat-demo/holder.pem \
  --tool write_file --path reports/q3.txt
```

```
BLOCKED before execution: Tool 'write_file' is not in the AAT leaf's authority (leaf permits: read_file)
tool invocations: 0  <- the tool never ran
```

And the file is untouched:

```bash
ls -l /tmp/aat-demo/reports/ && cat /tmp/aat-demo/reports/q3.txt
```

```
Q3 revenue: up and to the right.
```

## 6. Optional closer - the argument constraint

If there is time, this is the sharpest beat: the tool is allowed, the *argument*
is not.

```bash
python3 integrations/aat/demo_call.py \
  --chain /tmp/aat-demo/leaf.json \
  --holder-key /tmp/aat-demo/holder.pem \
  --tool read_file --path /etc/passwd
```

```
BLOCKED before execution: ConstraintViolation: Constraint 'path' not satisfied: value does not match constraint
tool invocations: 0  <- the tool never ran
```

Same tool that succeeded a moment ago. Different argument. Still blocked, still
before execution.

---

## If something goes wrong on the day

| Symptom | Cause | Fix |
|---|---|---|
| `DENY: AAT authority is not available (VOUCH_AAT_CHAIN is not set)` | The flag did not reach the server. | Check `--aat-chain`, or set `VOUCH_AAT_CHAIN` in `env`. |
| `DENY: AAT authority is not available (AAT adapter unavailable ...)` | `integrations/` is not importable. | Set `PYTHONPATH` to the repo root. |
| `AAT chain did not verify: AatExpired` | The demo chain aged out. | Re-run `demo_setup.py`; it mints a fresh hour-long chain. |
| Everything denies, including `read_file` | No holder key, so no proof-of-possession. | Pass `--aat-holder-key /tmp/aat-demo/holder.pem`. |

One honesty note for the recording: `--aat-holder-key` lets the server mint the
proof-of-possession itself, which keeps the demo to one terminal. In a real
deployment the PoP is produced by the caller that holds the key and passed in
with the call.
