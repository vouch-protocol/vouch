# Vouch MCP demo guide

Four scenes. Every command below has been run as written, and every claim in the
narration is true of code in this repository.

The through-line: **the check is not in the model. It's in the tool.**

`vouch-mcp` is a signer. It holds a key and issues credentials, and it can
refuse to sign. But it cannot stop a client from calling some other tool server,
so a demo built only on it shows advice, not enforcement. The second server,
built on `vouch.mcp.FastMCP`, is where the enforcement lives: it refuses to act
unless a verified credential authorises exactly the call being made.

---

## Setup, once, before recording

```bash
cd /path/to/vouch-protocol
pip install "vouch-protocol[mcp]"

rm -rf /tmp/vouch-demo
python3 examples/mcp_server/setup_demo.py --out /tmp/vouch-demo
```

That mints a `did:key` identity, writes a Shield rules file naming it, and
creates two files to act on:

```
/tmp/vouch-demo/reports/q3.txt     <- the agent may read this
/tmp/vouch-demo/secrets/keys.txt   <- it may not
```

The rules say one thing: this DID may `read_file` and `list_dir` under
`reports/**`. Nothing else.

Export what the script prints:

```bash
export VOUCH_FS_ROOT="/tmp/vouch-demo"
export VOUCH_RULES="/tmp/vouch-demo/rules.yaml"
export VOUCH_TRUSTED_ISSUERS="did:key:z6Mk..."   # from the setup output
export VOUCH_TARGET="files"
export VOUCH_DID="did:key:z6Mk..."               # the same DID
export VOUCH_PRIVATE_KEY="$(cat /tmp/vouch-demo/agent.jwk)"
```

Claude Desktop config, if you are recording in the app:

```json
{
  "mcpServers": {
    "vouch": {
      "command": "vouch-mcp",
      "env": {
        "VOUCH_DID": "did:key:z6Mk...",
        "VOUCH_PRIVATE_KEY": "PASTE_agent.jwk_CONTENTS",
        "VOUCH_RULES": "/tmp/vouch-demo/rules.yaml"
      }
    },
    "files": {
      "command": "python3",
      "args": ["/path/to/vouch-protocol/examples/mcp_server/server.py"],
      "env": {
        "VOUCH_FS_ROOT": "/tmp/vouch-demo",
        "VOUCH_RULES": "/tmp/vouch-demo/rules.yaml",
        "VOUCH_TRUSTED_ISSUERS": "did:key:z6Mk...",
        "VOUCH_TARGET": "files",
        "PYTHONPATH": "/path/to/vouch-protocol"
      }
    }
  }
}
```

Keep the `files` server's stderr on screen. Its log is half the demo.

---

## Scene 1 - allowed

**In Claude:** *"Sign a read_file on reports/q3.txt, then use it to read the
file."*

Claude calls `vouch.sign`:

```
action=read_file  target=files  resource=reports/q3.txt
```

and gets a credential back. Then it calls `files.read_file` with that credential
attached. The server log shows:

```
ALLOW  did:key:z6Mk...  read_file  reports/q3.txt
```

and the contents come back: `Q3 revenue: up and to the right.`

**Terminal equivalent**, if you would rather not depend on the model:

```bash
python3 -c "
from vouch.integrations.mcp import server as notary
open('/tmp/vouch-demo/cred.json','w').write(
    notary.sign(action='read_file', target='files', resource='reports/q3.txt'))
print(open('/tmp/vouch-demo/cred.json').read()[:120], '...')
"
```

**Say:** *"The agent asked for permission for one action on one file, and got a
signed credential saying so."*

---

## Scene 2 - refused at the notary

**In Claude:** *"Sign a delete_file on reports/q3.txt."*

```bash
python3 -c "
from vouch.integrations.mcp import server as notary
print(notary.sign(action='delete_file', target='files', resource='reports/q3.txt'))
"
```

```json
{"error":"refused","reason":"no matching rule","action":"delete_file","target":"files","resource":"reports/q3.txt"}
```

No credential exists. There is nothing to present.

**Say:** *"Nothing to present. The notary won't stamp it."*

---

## Scene 2b - refused at the door (the money shot)

Scene 2 could be argued away: the model just did not get a credential, and a
determined model might route around the notary. This scene closes that.

Show the import line on screen for two seconds:

```python
from vouch.mcp import FastMCP          # was: from mcp.server.fastmcp import FastMCP
```

**Say:** *"This is a standard MCP server with one import changed. Every tool
checks before it acts."*

### (i) A valid credential, pointed at a different file

Take the credential from Scene 1 - genuinely valid, correctly signed, for
`read_file reports/q3.txt` - and use it to ask for `reports/q4.txt`.

```bash
python3 - <<'EOF'
import asyncio, importlib.util, json
spec = importlib.util.spec_from_file_location("fs", "examples/mcp_server/server.py")
fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)
cred = open('/tmp/vouch-demo/cred.json').read()
try:
    print(asyncio.run(fs.mcp.call_tool("read_file", {"path": "reports/q4.txt", "credential": cred})))
except Exception as e:
    print("REFUSED:", str(e).split("{",1)[-1])
EOF
```

```
REFUSED: "error":"refused","reason":"credential does not match request",...
```

Server log:

```
DENY   did:key:z6Mk...  read_file  reports/q4.txt  credential does not match request
```

### (ii) A credential for a path outside the rules

Ask the notary for `secrets/keys.txt`. It refuses too - defence in depth:

```bash
python3 -c "
from vouch.integrations.mcp import server as notary
print(notary.sign(action='read_file', target='files', resource='secrets/keys.txt'))
"
```

```json
{"error":"refused","reason":"resource outside scope",...}
```

So to show the *door* refusing, sign one by hand, bypassing the notary entirely -
exactly what a compromised agent with the key would do:

```bash
python3 - <<'EOF'
import asyncio, importlib.util, json, os
from vouch.signer import Signer
spec = importlib.util.spec_from_file_location("fs", "examples/mcp_server/server.py")
fs = importlib.util.module_from_spec(spec); spec.loader.exec_module(fs)

signer = Signer(private_key=os.environ["VOUCH_PRIVATE_KEY"], did=os.environ["VOUCH_DID"])
rogue = json.dumps(signer.sign(action="read_file", target="files",
                               resource="secrets/keys.txt"))
try:
    print(asyncio.run(fs.mcp.call_tool("read_file", {"path": "secrets/keys.txt", "credential": rogue})))
except Exception as e:
    print("REFUSED:", str(e).split("{",1)[-1])
EOF
```

```
REFUSED: "error":"refused","reason":"resource outside scope",...
```

Server log:

```
DENY   did:key:z6Mk...  read_file  secrets/keys.txt  resource outside scope
```

That credential is **cryptographically perfect**. It verifies. It is from a
trusted issuer. It matches the request exactly. And the file is still not read,
because the server's own rules do not permit that path.

### (iii) Nothing was touched

```bash
ls -R /tmp/vouch-demo/reports /tmp/vouch-demo/secrets
cat /tmp/vouch-demo/secrets/keys.txt
```

```
this file must never be read
```

Still there, still unread by the agent.

**Say:** *"The check isn't in the model. It's in the tool."*

---

## Scene 3 - verified by a stranger

Anyone can check the Scene 1 credential without trusting the demo, without an
SDK, and without asking either server.

```bash
vouch verify "$(cat /tmp/vouch-demo/cred.json)"
```

```
✅ VALID
   Subject: did:key:z6Mk...
   Issuer:  did:key:z6Mk...
   Intent:  {"action": "read_file", "target": "files", "resource": "reports/q3.txt"}
```

**Say:** *"A third party can confirm what was authorised, months later, offline.
The credential is the evidence."*

---

## Scene 4 - AAT: delegation narrowed offline

Attenuating Authorization Tokens are an IETF draft for OAuth-world agent
delegation. A holder can narrow a token offline, with no authorization server.
This scene shows one of those narrowed tokens driving Vouch's rules.

```bash
rm -rf /tmp/aat-demo
python3 integrations/aat/demo_setup.py --out /tmp/aat-demo
```

```
  root AAT grants : read_file, write_file on reports/*
  leaf AAT grants : read_file on reports/*
Narrowed offline. No authorization server was contacted.
```

Now show the leaf's constraint becoming a Shield rule, and Shield enforcing it:

```bash
python3 - <<'EOF'
import sys; sys.path.insert(0, '.')
from integrations.aat import verify_chain_file, AatGate
from tenuo import SigningKey

chain = verify_chain_file('/tmp/aat-demo/leaf.json')
key = SigningKey.from_pem(open('/tmp/aat-demo/holder.pem').read())
gate = AatGate(chain, holder_key=key, did="did:key:demo", target="files")

print("Shield rules derived from the AAT leaf:")
for r in gate.rules.rules:
    print(f"  action={r.action}  target={r.target}  resource={r.resource}")
print()
for tool, path in [("read_file", "reports/q3.txt"),
                   ("read_file", "secrets/keys.txt"),
                   ("write_file", "reports/q3.txt")]:
    d = gate.shield_check(tool, {"path": path})
    print(f"  {tool:11} {path:20} -> {'ALLOW' if d.allow else 'DENY: ' + d.reason}")
EOF
```

```
Shield rules derived from the AAT leaf:
  action=read_file  target=files  resource=reports/*/**

  read_file   reports/q3.txt       -> ALLOW
  read_file   secrets/keys.txt     -> DENY: resource outside scope
  write_file  reports/q3.txt       -> DENY: no matching rule
```

`write_file` was in the root and narrowed out of the leaf. `secrets/keys.txt` is
refused by **Shield**, from a rule derived from the token's own path constraint.

**Say:** *"OAuth-world delegation, narrowed offline; enforced here, before the
call."*

---

## If something goes wrong on the day

| Symptom | Cause | Fix |
|---|---|---|
| Every call refused with `unknown did` | The rules file names a different DID | Re-run `setup_demo.py` and re-export |
| `credential did not verify` on a fresh credential | Clock skew, or the signer's DID is not `did:key` | Check `VOUCH_DID` matches `agent.jwk` |
| Server exits with `VOUCH_RULES is not set` | Missing config | That is the design: it refuses to start unprotected |
| `files` server not visible in Claude | `PYTHONPATH` missing | Set it to the repo root in the config |
| `no credential` on every call | The client is not passing `credential` | It is a required argument on every protected tool |

## What each scene proves

| Scene | Claim |
|---|---|
| 1 | An agent can obtain narrow, signed authority for one action on one resource |
| 2 | The signer refuses to attest what policy forbids |
| 2b | The tool server refuses independently, even given a perfect credential |
| 3 | A third party can verify the record offline, later |
| 4 | Delegation narrowed offline in another ecosystem enforces here, before the call |
