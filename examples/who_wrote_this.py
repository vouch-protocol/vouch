#!/usr/bin/env python3
"""
Who Wrote This: a demo of per-region human/AI code attribution.

Run it:

    pip install vouch-protocol
    python who_wrote_this.py

An AI assistant and a human edit the same file. git blame would credit every
line to the human who committed it. Vouch records who actually wrote each line,
signs the AI's lines with the AI's own key and the human's with the human's,
and lets anyone verify it. Then it shows that you cannot forge an AI line or
alter a single byte without breaking the proof.

Everything runs locally in a temporary directory. No servers, no setup.
"""

import copy
import tempfile

from vouch import Signer, generate_identity
from vouch import attribution as attr

G = "\033[92m"; R = "\033[91m"; AI = "\033[95m"; HU = "\033[96m"
DIM = "\033[2m"; BOLD = "\033[1m"; END = "\033[0m"


def line(char="-", n=64):
    print(DIM + char * n + END)


def main() -> None:
    tmp = tempfile.mkdtemp()
    print()
    print(f"{BOLD}WHO WROTE THIS{END}  {DIM}a Vouch Protocol demo{END}")
    line("=")

    # The human's identity, and a session that holds the AI's separate key.
    human = generate_identity(domain="dev.acme.com")
    human_signer = Signer(private_key=human.private_key_jwk, did=human.did)
    session = attr.AttributionSession(tmp, model="claude-opus-4-8")
    print(f"{HU}human{END} : {human.did}")
    print(f"{AI}AI   {END} : {session.ai_did}")
    print(f"{DIM}Two separate keys. Neither party can sign as the other.{END}")
    print()

    # Act 1: the AI writes the first version.
    print(f"{BOLD}Act 1.{END} The AI assistant writes a handler.")
    line()
    v1 = (
        "import os\n"
        "def handler(event):\n"
        "    return event[\"id\"]\n"
    )
    session.record_edit("app.py", v1)
    print(f"{AI}AI wrote 3 lines.{END}")
    print()

    # Act 2: the human edits one line and adds two, without the AI.
    print(f"{BOLD}Act 2.{END} The human fixes a bug and adds an audit function.")
    line()
    v2 = (
        "import os\n"
        "def handler(event):\n"
        "    return event[\"order_id\"]\n"   # human fixes the key
        "def audit(event):\n"               # human adds
        "    log(event)\n"                   # human adds
    )
    # The human's edit did not come through the assistant. It is the residual.

    # Act 3: the AI adds one more function on top of the human's version.
    print(f"{BOLD}Act 3.{END} The AI adds a retry helper.")
    line()
    v3 = v2 + "def retry(event):\n    return handler(event)\n"
    session.record_edit("app.py", v3, before_content=v2)
    print(f"{AI}AI wrote 2 more lines.{END}")
    print()

    # Finalize: the human signs the manifest; the AI's regions carry the AI key.
    manifest = session.finalize({"app.py": v3}, human_signer)

    print(f"{BOLD}The signed attribution:{END}")
    line()
    content = v3.split("\n")
    for entry in attr.blame(manifest, "app.py"):
        n = entry["line"]
        text = content[n - 1] if n - 1 < len(content) else ""
        if entry["source"] == attr.SOURCE_AI:
            tag = f"{AI}AI   {END}"
        elif entry["source"] == attr.SOURCE_HUMAN:
            tag = f"{HU}human{END}"
        else:
            tag = f"{DIM}prior{END}"
        print(f"  {tag} {n} | {text}")
    s = attr.summarize(manifest)
    print()
    print(f"  {AI}AI{END} {s['aiPercent']}%    {HU}human{END} {s['humanPercent']}%")
    print()

    # Verify the honest manifest.
    ok = attr.verify_manifest(
        manifest, human.public_key_jwk, session.ai_public_key_jwk,
        files_on_disk={"app.py": v3},
    )
    print(f"{BOLD}Verify the real manifest:{END} ", end="")
    print(f"{G}{BOLD}VERIFIED{END}" if ok.ok else f"{R}{BOLD}FAILED{END}")

    # Attack 1: relabel the human's bug-fix line as AI-written.
    forged = copy.deepcopy(manifest)
    for f in forged["files"]:
        for r in f["regions"]:
            if r["source"] == attr.SOURCE_HUMAN:
                r["source"] = attr.SOURCE_AI
                r["author"] = session.ai_did
    forged_ok = attr.verify_manifest(forged, human.public_key_jwk, session.ai_public_key_jwk)
    print(f"{BOLD}Blame the AI for a human line:{END} ", end="")
    print(f"{R}{BOLD}REJECTED{END}" if not forged_ok.ok else f"{G}ACCEPTED{END}")

    # Attack 2: change one byte of the committed file.
    tampered_bytes = v3.replace("order_id", "evil_id")
    tampered_ok = attr.verify_manifest(
        manifest, human.public_key_jwk, session.ai_public_key_jwk,
        files_on_disk={"app.py": tampered_bytes},
    )
    print(f"{BOLD}Alter one byte after signing:{END} ", end="")
    print(f"{R}{BOLD}REJECTED{END}" if not tampered_ok.ok else f"{G}ACCEPTED{END}")

    print()
    line("=")
    invariant = ok.ok and (not forged_ok.ok) and (not tampered_ok.ok)
    if invariant:
        print(f"{G}{BOLD}Every line has an author you can prove. Nobody can wear the other's name.{END}")
    else:
        print(f"{R}Demo invariant failed.{END}")
    print(f"{DIM}This is Vouch Protocol attribution. See vouch/integrations/claude-code/.{END}")
    print()
    raise SystemExit(0 if invariant else 1)


if __name__ == "__main__":
    main()
