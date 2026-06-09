# Vouch Protocol — Install, Run, and Confidence-Build Guide

**For:** the editor and anyone who has never actually run Vouch before and wants to verify, by hand, that everything in the spec actually works.

**Time to complete:** 45-60 minutes if you do every variation, ~15 minutes if you just want the happy path.

**Outcome:** you finish this confident that you can demo Vouch on a CCG call without anything surprising you.

---

## Pre-flight: what you need on your machine

You're on WSL Ubuntu. Check each:

```bash
python3 --version          # >= 3.9 required; 3.11 or 3.12 ideal
pip --version              # any recent version
git --version              # any recent version
node --version             # >= 20 (only needed for TypeScript demo)
go version                 # >= 1.21 (only needed for Go demo)
curl --version             # any
jq --version               # for pretty-printing JSON; install via apt if missing
```

If any of these are missing:

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git curl jq nodejs npm golang-go
```

---

## Phase 1: Install Vouch Protocol from PyPI (5 minutes)

Goal: confirm the `vouch` CLI works on your machine.

```bash
# Create a clean virtual environment so this doesn't pollute your system Python
python3 -m venv ~/vouch-demo-venv
source ~/vouch-demo-venv/bin/activate

# Install from PyPI
pip install --upgrade pip
pip install vouch-protocol

# Confirm it landed
vouch --version
which vouch
```

**Expected output of `vouch --version`:** `1.6.0` (or whatever PyPI has).

**If `pip install` fails:** read the error. Most likely cause is `c2pa-python` needing Rust to build a native dep. If you don't need media signing for this demo, you can install a lighter subset:

```bash
pip install vouch-protocol --no-deps
pip install jwcrypto cryptography pyyaml requests python-dateutil
```

**Verify the CLI surface:**

```bash
vouch --help
```

You should see subcommands including `init`, `sign`, `verify`, `git`, `media`, `scan`.

**Validation gate:** if `vouch --help` prints the subcommand list, Phase 1 is done.

---

## Phase 2: The happy path — init, sign, verify (5 minutes)

Goal: produce one Verifiable Credential and verify it end-to-end.

### Step 2.1: Generate an identity

```bash
mkdir -p ~/vouch-demo && cd ~/vouch-demo

# Generate environment variables (DID + private key) instead of writing to keystore
vouch init --domain demo.vouch-protocol.com --env > identity.env

# Inspect what got created
cat identity.env
```

**Expected output:**

```
export VOUCH_DID='did:web:demo.vouch-protocol.com'
export VOUCH_PRIVATE_KEY='{"kty":"OKP","crv":"Ed25519","d":"...","x":"..."}'
# Public Key (for vouch.json): ...
```

The `# Public Key` line is on stderr; what's in the file are the two `export` lines plus an inline comment.

```bash
source identity.env
echo "DID:        $VOUCH_DID"
echo "Private key (truncated): ${VOUCH_PRIVATE_KEY:0:50}..."
```

### Step 2.2: Sign an intent

```bash
ACTION='{"action":"read","target":"customer","resource":"acct:42"}'

# Sign produces a Verifiable Credential with a Data Integrity proof
CRED=$(vouch sign "$ACTION" --json --key "$VOUCH_PRIVATE_KEY" --did "$VOUCH_DID")

# Print and pretty-format
echo "$CRED" | jq .
```

**Expected output (truncated):**

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://vouch-protocol.com/contexts/vouch/v1"
  ],
  "type": ["VerifiableCredential", "VouchCredential"],
  "issuer": "did:web:demo.vouch-protocol.com",
  "validFrom": "2026-06-01T...",
  "validUntil": "2026-06-01T... (~300 s later)",
  "credentialSubject": {
    "intent": {
      "action": "read",
      "target": "customer",
      "resource": "acct:42"
    }
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-06-01T...",
    "verificationMethod": "did:web:demo.vouch-protocol.com#key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "z..."
  }
}
```

**What to look for in the output:** the `proof.cryptosuite` says `eddsa-jcs-2022`, the credential is plain readable JSON (no base64 blob), the `credentialSubject.intent` triple matches what you put in.

### Step 2.3: Verify

```bash
echo "$CRED" | vouch verify --json -
```

**Expected output:**

```
✓ Credential signature verified
  Issuer: did:web:demo.vouch-protocol.com
  Cryptosuite: eddsa-jcs-2022
  Valid from: 2026-06-01T...
  Valid until: 2026-06-01T...
```

Exit code: 0 on success, non-zero on failure.

**Validation gate:** if you see "Credential signature verified", Phase 2 is done. You have proven the round trip works.

---

## Phase 3: Negative tests (5 minutes)

Goal: prove the verifier actually catches tampering. If it accepts a bad credential, your demo is dangerous.

### Test 3.1: Tamper with the intent, expect verification failure

```bash
TAMPERED=$(echo "$CRED" | jq '.credentialSubject.intent.action = "delete"')
echo "$TAMPERED" | vouch verify --json -
```

**Expected:** non-zero exit, message about signature mismatch or proof invalid.

If this PASSES verification, something is broken. Stop and investigate.

### Test 3.2: Tamper with the issuer DID

```bash
TAMPERED=$(echo "$CRED" | jq '.issuer = "did:web:evil.example.com"')
echo "$TAMPERED" | vouch verify --json -
```

**Expected:** non-zero exit. Either signature mismatch, or DID resolution failure.

### Test 3.3: Expired credential (depends on `validUntil` past)

Wait ~5 minutes (the default `validUntil` is +300 seconds from issuance), then:

```bash
echo "$CRED" | vouch verify --json -
```

**Expected:** verification fails with "credential expired" or equivalent.

(Skip this in the live demo unless you've pre-prepared an expired credential.)

**Validation gate:** all three negative tests fail verification cleanly. You now trust the verifier.

---

## Phase 4: Inspect what's actually being signed (3 minutes)

Goal: see the JCS canonicalization with your own eyes.

```bash
# Strip the proof, canonicalize the rest
echo "$CRED" | jq 'del(.proof)' | python3 -c "
import sys, json
doc = json.load(sys.stdin)
# JCS = sorted keys, no spaces, no trailing newline
print(json.dumps(doc, sort_keys=True, separators=(',', ':')), end='')
" > /tmp/canonical.txt

wc -c /tmp/canonical.txt
head -c 200 /tmp/canonical.txt
echo
```

This is the exact byte sequence that gets hashed and signed. The same bytes would be produced by any conforming JCS implementation in any language. This is the "byte-identical determinism" the spec calls out in §15.

---

## Phase 5: Cross-implementation byte-identical credentials (10 minutes)

Goal: prove that Python, TypeScript, and Go all produce the same canonical bytes for the same input. This is the demo you want for the CCG call.

You need the local repo (not the pip-installed package) for this, because the cross-impl test vectors live there.

```bash
cd ~/vouch-protocol  # or wherever you cloned it
ls tests/interop/ 2>/dev/null || ls tests/test_interop* 2>/dev/null
```

If `tests/interop/` doesn't exist, look around for `test_vectors/`, `vectors/`, or `interop/`:

```bash
find . -type d -name "*interop*" -not -path "*/node_modules/*" 2>/dev/null | head
find . -type d -name "*vectors*" -not -path "*/node_modules/*" 2>/dev/null | head
```

Adjust the paths below to match whatever you find.

### Python side: sign with the Python implementation

```bash
cd ~/vouch-protocol
source ~/vouch-demo-venv/bin/activate
# Make sure you're using the local install, not PyPI
pip install -e .
```

Create a tiny script that signs with a fixed test key (so all three implementations can compare):

```bash
cat > /tmp/sign-py.py <<'EOF'
from vouch.signer import Signer
import json

# Fixed test key (same one used in TS and Go for comparison)
TEST_KEY = '{"kty":"OKP","crv":"Ed25519","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","x":"OkwzWHIaIxxRPLrPzPLcvIuFcCpUiu3w4-yqI8Bz9XU"}'
TEST_DID = "did:web:test.example.com"
TEST_INTENT = {"action": "read", "target": "customer", "resource": "acct:42"}
TEST_VALID_FROM = "2026-06-01T00:00:00Z"

signer = Signer(private_key_jwk=TEST_KEY, did=TEST_DID)
cred = signer.sign_credential(intent=TEST_INTENT, valid_from=TEST_VALID_FROM, valid_until_seconds=300)
print(json.dumps(cred, sort_keys=True, separators=(',', ':')))
EOF

python3 /tmp/sign-py.py > /tmp/cred-py.json
head -c 200 /tmp/cred-py.json
echo
sha256sum /tmp/cred-py.json
```

**Expected:** a JCS-canonical JSON credential, ~600-800 bytes, with a SHA-256 hash.

### TypeScript side

```bash
cd ~/vouch-protocol/packages/sdk-ts
npm install
npm run build

cat > /tmp/sign-ts.mjs <<'EOF'
import { Signer } from '/home/rampy/vouch-protocol/packages/sdk-ts/dist/signer.js';

const TEST_KEY = '{"kty":"OKP","crv":"Ed25519","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","x":"OkwzWHIaIxxRPLrPzPLcvIuFcCpUiu3w4-yqI8Bz9XU"}';
const TEST_DID = "did:web:test.example.com";
const TEST_INTENT = { action: "read", target: "customer", resource: "acct:42" };
const TEST_VALID_FROM = "2026-06-01T00:00:00Z";

const signer = new Signer({ privateKeyJwk: JSON.parse(TEST_KEY), did: TEST_DID });
const cred = await signer.signCredential({ intent: TEST_INTENT, validFrom: TEST_VALID_FROM, validUntilSeconds: 300 });
// JCS-canonical output
process.stdout.write(JSON.stringify(cred, Object.keys(cred).sort(), 0));
EOF

node /tmp/sign-ts.mjs > /tmp/cred-ts.json
sha256sum /tmp/cred-ts.json
```

### Go side

```bash
cd ~/vouch-protocol/go-sidecar
go build -o /tmp/vouch-go ./cmd/vouch-cli  # adjust path if different

# Use the Go binary's sign command (or write a small main.go if needed)
/tmp/vouch-go sign \
  --key '{"kty":"OKP","crv":"Ed25519","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","x":"OkwzWHIaIxxRPLrPzPLcvIuFcCpUiu3w4-yqI8Bz9XU"}' \
  --did did:web:test.example.com \
  --intent '{"action":"read","target":"customer","resource":"acct:42"}' \
  --valid-from 2026-06-01T00:00:00Z \
  --valid-until-seconds 300 \
  > /tmp/cred-go.json

sha256sum /tmp/cred-go.json
```

### Compare

```bash
sha256sum /tmp/cred-py.json /tmp/cred-ts.json /tmp/cred-go.json
diff /tmp/cred-py.json /tmp/cred-ts.json && echo "Python and TS identical"
diff /tmp/cred-ts.json /tmp/cred-go.json && echo "TS and Go identical"
diff /tmp/cred-py.json /tmp/cred-go.json && echo "Python and Go identical"
```

**Expected:** all three SHA-256 hashes identical, all three `diff` commands print no differences and the "identical" message.

If they're NOT identical: the SDK packages haven't been built with the same JCS rules. Check:
- Are all three using RFC 8785 JCS? (Not custom-sort-keys, not JSON-LD canonicalization.)
- Same `validFrom` timestamp? (If you let the SDK auto-fill, it'll use `now()` and the three will differ on timestamp.)
- Same private key bytes? (The example test key above uses all-zeros private scalar for determinism. Real deployments use random keys.)

**Validation gate:** all three implementations produce byte-identical credentials. This is the centerpiece of your CCG demo.

---

## Phase 6: Git integration (5 minutes)

Goal: see Vouch's git-signing integration work end-to-end on a throwaway repo.

```bash
mkdir -p /tmp/vouch-git-test && cd /tmp/vouch-git-test
git init
echo "# Test" > README.md
git add README.md

# Configure Vouch git signing for this repo
vouch git init

# Make a commit (the prepare-commit-msg hook adds Vouch trailers)
git commit -m "Initial commit"
git log --pretty=full -1
```

**Expected:** `git log` shows a commit with extra trailers:

```
Signed-off-by: Vouch Protocol <Identity-Sidecar>
Vouch-DID: did:web:demo.vouch-protocol.com
```

Verify any Vouch-signed commit:

```bash
vouch git verify HEAD
```

**Expected:** confirms the commit's Vouch trailer matches the configured DID.

**Validation gate:** `vouch git verify HEAD` reports success.

---

## Phase 7: Dual-proof post-quantum profile (8 minutes)

Goal: produce a credential with both an Ed25519 proof and an ML-DSA-44 proof, and verify each independently.

This needs the local repo install (Phase 5 prereqs) because it uses `vouch.data_integrity_hybrid`.

```bash
cd ~/vouch-protocol
python3 << 'EOF'
from vouch.signer import Signer
from vouch.data_integrity_hybrid import sign_vc_hybrid
from vouch.keys import generate_identity
import json

# Generate fresh identity that will hold BOTH an Ed25519 key and an ML-DSA-44 key
ident = generate_identity("dual-demo.example.com", include_mldsa=True)
print("DID:", ident.did)

signer = Signer(private_key_jwk=ident.private_key_jwk, did=ident.did)
intent = {"action": "transfer", "target": "account", "resource": "acct:42"}
vc_unsigned = signer.build_vc(intent=intent)

# Apply both proofs
vc_dual = sign_vc_hybrid(vc_unsigned, signer)

print(json.dumps(vc_dual, indent=2)[:1000])
print(f"\nNumber of proofs: {len(vc_dual.get('proof', []))}")
for i, p in enumerate(vc_dual.get("proof", [])):
    print(f"  proof[{i}].cryptosuite = {p.get('cryptosuite')}")
EOF
```

**Expected:** the credential's `proof` field is an array with two entries: one `eddsa-jcs-2022`, one `mldsa44-jcs-2026`. The same `credentialSubject` and `validFrom` etc. are present.

**Verify Mode A (classical only):**

```bash
python3 << 'EOF'
# Verify only the eddsa-jcs-2022 proof
from vouch.verifier import Verifier
import json

vc = json.load(open("/tmp/cred-dual.json"))   # adjust path; save the above output here
v = Verifier()
result = v.verify_credential(vc, required_cryptosuites=["eddsa-jcs-2022"])
print("Mode A (classical):", "PASS" if result.valid else "FAIL")
EOF
```

**Verify Mode B (post-quantum only):**

```bash
python3 << 'EOF'
from vouch.verifier import Verifier
import json
vc = json.load(open("/tmp/cred-dual.json"))
v = Verifier()
result = v.verify_credential(vc, required_cryptosuites=["mldsa44-jcs-2026"])
print("Mode B (post-quantum):", "PASS" if result.valid else "FAIL")
EOF
```

**Verify Mode C (both required):**

```bash
python3 << 'EOF'
from vouch.verifier import Verifier
import json
vc = json.load(open("/tmp/cred-dual.json"))
v = Verifier()
result = v.verify_credential(vc, required_cryptosuites=["eddsa-jcs-2022", "mldsa44-jcs-2026"])
print("Mode C (both):", "PASS" if result.valid else "FAIL")
EOF
```

**Expected:** all three modes pass when the dual-proof credential is verified.

**Tampering test for dual-proof:** modify the credential, run all three modes again, expect all three to fail.

**Validation gate:** Mode A, B, and C all pass; Mode A and B independently catch tampering.

---

## Phase 8: Inspecting a delegation chain (3 minutes)

Goal: see a multi-link delegation chain and verify resource binding.

```bash
python3 << 'EOF'
from vouch.signer import Signer
from vouch.keys import generate_identity
import json

# Root principal
root = generate_identity("principal.example.com")
root_signer = Signer(private_key_jwk=root.private_key_jwk, did=root.did)

# Coordinator agent
coord = generate_identity("coord.agent.example.com")
coord_signer = Signer(private_key_jwk=coord.private_key_jwk, did=coord.did)

# Worker agent
worker = generate_identity("worker.agent.example.com")
worker_signer = Signer(private_key_jwk=worker.private_key_jwk, did=worker.did)

# Root delegates to coordinator (resource = acct:42, action = read)
delegation_1 = root_signer.sign_credential(
    intent={"action": "read", "target": "account", "resource": "acct:42"},
    subject_did=coord.did,
)
# Coordinator delegates a narrower scope to worker (same resource, same action)
delegation_2 = coord_signer.sign_credential(
    intent={"action": "read", "target": "account", "resource": "acct:42"},
    subject_did=worker.did,
    parent_credential=delegation_1,
)

print(json.dumps(delegation_2, indent=2))
EOF
```

**Expected:** the worker's credential carries a chain pointing back to the coordinator's delegation, which points back to the root principal. Every link binds `resource: "acct:42"`.

**Try to violate the rules — expected to fail:**

```bash
# Worker tries to widen scope (acct:42 -> acct:*); should fail validation
python3 << 'EOF'
from vouch.signer import Signer
from vouch.verifier import Verifier
# ... try to sign with broader resource, then verify; verifier should reject
# (Implementation-specific; check the spec §9 chain validation rules)
EOF
```

**Validation gate:** widening attempts fail; narrowing chains validate.

---

## Phase 9: Cleanup and reset

```bash
deactivate                                 # leave the venv
rm -rf ~/vouch-demo-venv ~/vouch-demo      # remove the local install + working dir
rm -f /tmp/cred-*.json /tmp/canonical.txt  # remove test artifacts
rm -f /tmp/sign-py.py /tmp/sign-ts.mjs     # remove demo scripts
```

The `vouch-protocol` PyPI package is gone. Your machine is back to where you started.

---

## Confidence checklist (run before the CCG call)

Walk through this from a cold start (no env, no installed package) and tick each box. Time yourself.

- [ ] **Phase 1 (Install):** `vouch --version` works.
- [ ] **Phase 2 (Happy path):** init → sign → verify, all green.
- [ ] **Phase 3 (Negative):** tampered credential fails to verify.
- [ ] **Phase 4 (Inspect):** you can show the JCS canonical bytes on screen.
- [ ] **Phase 5 (Cross-impl):** Python, TS, Go all produce the same SHA-256.
- [ ] **Phase 6 (Git):** `vouch git init` configures, commit gets Vouch trailers, `vouch git verify` succeeds.
- [ ] **Phase 7 (Dual-proof):** credential has two proofs, all three verifier modes pass.
- [ ] **Phase 8 (Delegation):** chain validates; widening attempts fail.
- [ ] **Phase 9 (Cleanup):** machine returns to baseline.

**Time the full sweep.** If it takes more than 45 minutes, you're explaining things in your head as you go (which is fine for confidence-building but means the actual live demo will be slower than you think).

---

## What to bring to the CCG call

A pre-warmed terminal that looks like this:

- Working directory: `~/vouch-demo`
- `identity.env` already sourced (so `$VOUCH_DID` and `$VOUCH_PRIVATE_KEY` are live)
- `cred-py.json`, `cred-ts.json`, `cred-go.json` from Phase 5 already produced and verified
- Font size: 18pt minimum, dark background (more readable on video calls)
- History cleared so command recall doesn't expose your test runs
- A pre-recorded asciinema or screen capture of Phase 5 ready as a backup tab if live demo gods are unkind

---

## If something doesn't work mid-demo

Three rules:

1. **Don't fight it.** "Let me show you the recorded version." Flip to the backup recording. Total time loss: 5 seconds.
2. **Don't promise to debug live.** "I'll follow up on the list with the fix." Move on.
3. **Don't apologize repeatedly.** Acknowledge once, continue. The CCG audience has seen demos fail; they care about the architecture, not the demo theatrics.

---

## What this guide is NOT

- Not a tutorial for users who want to integrate Vouch into a production system. For that, point them at the README, the spec, and the SDK docs.
- Not a stress test or load test. We're confirming correctness, not performance.
- Not exhaustive. Section §10 (Identity Sidecar with MCP), §11.7 (Canary Commitments), §15 (State Verifiability), and the algorithm-quorum mode of §13.6 are not exercised here; they would each warrant their own walkthrough.

The point is to give you, the editor, end-to-end confidence that the spec describes something real and that you can demonstrate it credibly to a W3C audience under time pressure.
