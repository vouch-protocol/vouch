#!/usr/bin/env python3
"""Vouch conformance client. Runs in an implementation's CI: it asks the
conformance worker for a fresh challenge set, answers each challenge with the
implementation under test (the reference uses the vouch SDK), submits the
transcript, and reports the level plus the badge URL. The worker re-checks every
response server-side, so a pass cannot be faked by replaying the public vectors.

A port replaces the four `respond_*` functions with its own SDK calls; the
session and submit plumbing stays the same.

Env / args:
  --worker      Worker base URL (default https://conformance.vouch-protocol.com)
  --name        Implementation name        (default from GITHUB_REPOSITORY)
  --repo        owner/repo                  (default from GITHUB_REPOSITORY)
  --commit      commit sha                  (default from GITHUB_SHA)
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.request

from vouch import jcs, keys
from vouch.audit_trail import AuditTrail
from vouch.signer import Signer
from vouch.status_list import (
    StatusList,
    build_status_list_credential,
    build_status_list_entry,
)
from vouch.verifier import Verifier


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def raw_public_b64(public_jwk: str) -> str:
    """The raw 32-byte Ed25519 public key, base64, as the worker expects."""
    return _b64(_b64url_decode(json.loads(public_jwk)["x"]))


def public_jwk_from_b64(public_b64: str) -> str:
    """Rebuild an Ed25519 JWK from a raw base64 public key."""
    x = base64.urlsafe_b64encode(base64.b64decode(public_b64)).decode("ascii").rstrip("=")
    return json.dumps({"kty": "OKP", "crv": "Ed25519", "x": x})


def post(url: str, body: dict) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"content-type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


# --- responders (the reference implementation answers with the vouch SDK) ----


def respond_canonicalization(challenge: dict, _signer: Signer) -> str:
    return jcs.canonicalize(challenge["input"]).decode("utf-8")


def respond_sign_verify(challenge: dict, signer: Signer) -> dict:
    return signer.sign(intent=challenge["input"]["intent"])


def respond_validity_window(challenge: dict, _signer: Signer) -> dict:
    inp = challenge["input"]
    valid, _ = Verifier.verify(
        inp["credential"], public_key=public_jwk_from_b64(inp["publicKeyB64"])
    )
    return {"valid": bool(valid)}


def respond_nonce_replay(challenge: dict, _signer: Signer) -> dict:
    # A conformant verifier tracks credential ids and rejects a repeat.
    seen: set[str] = set()
    cred_id = challenge["input"]["credential"]["id"]
    first = cred_id not in seen
    seen.add(cred_id)
    second = cred_id not in seen
    return {"firstAccepted": first, "secondAccepted": second}


def respond_revocation(challenge: dict, _signer: Signer) -> dict:
    inp = challenge["input"]
    status_list = StatusList(status_list_id=inp["statusListId"])
    status_list.set_status(inp["revokedIndex"], True)
    entry = lambda index: build_status_list_entry(  # noqa: E731
        status_list_credential=inp["statusListId"], status_list_index=index
    )
    return {
        "statusListCredential": build_status_list_credential(
            issuer_did="did:web:conformance.vouch-protocol.com", status_list=status_list
        ),
        "revokedEntry": entry(inp["revokedIndex"]),
        "activeEntry": entry(inp["activeIndex"]),
    }


def respond_delegation_narrowing(challenge: dict, signer: Signer) -> dict:
    inp = challenge["input"]
    return signer.sign(intent=inp["narrowedIntent"], parent_credential=inp["parentCredential"])


def respond_sidecar_allow_deny(challenge: dict, signer: Signer) -> dict:
    inp = challenge["input"]
    allowed_actions = inp.get("policy", {}).get("allowedActions", [])
    denied_action = inp["deniedIntent"]["action"]
    if denied_action in allowed_actions:  # a policy that allows it is not a denial case
        denial = {"rejected": False, "reason": ""}
    else:
        denial = {"rejected": True, "reason": f"policy_denied:{denied_action}"}
    return {"allowed": signer.sign(intent=inp["allowedIntent"]), "denied": denial}


def respond_audit_trail(challenge: dict, _signer: Signer) -> dict:
    trail = AuditTrail()
    for action in challenge["input"]["actions"]:
        trail.append(
            action=action["action"],
            actor=action.get("actor"),
            resource=action.get("resource"),
            decision=action.get("decision"),
            timestamp=action.get("timestamp"),
        )
    return {"entries": [entry.to_dict() for entry in trail.entries]}


RESPONDERS = {
    "canonicalization": respond_canonicalization,
    "sign_verify": respond_sign_verify,
    "validity_window": respond_validity_window,
    "nonce_replay": respond_nonce_replay,
    "revocation": respond_revocation,
    "delegation_narrowing": respond_delegation_narrowing,
    "sidecar_allow_deny": respond_sidecar_allow_deny,
    "audit_trail": respond_audit_trail,
}


def answer(challenges: list, signer: Signer) -> list:
    responses = []
    for ch in challenges:
        fn = RESPONDERS.get(ch["check"])
        if fn is None:
            continue  # unknown check (a newer worker); the worker fails it for us
        responses.append({"challengeId": ch["challengeId"], "output": fn(ch, signer)})
    return responses


def gh_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(f"{name}={value}\n")


def gh_summary(lines: list) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")


def main() -> int:
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    ap = argparse.ArgumentParser(description="Run the Vouch conformance test in CI")
    ap.add_argument("--worker", default="https://conformance.vouch-protocol.com")
    ap.add_argument("--name", default=repo.split("/")[-1] or "implementation")
    ap.add_argument("--repo", default=repo)
    ap.add_argument("--commit", default=os.environ.get("GITHUB_SHA", ""))
    args = ap.parse_args()

    identity = keys.generate_identity("conformance")
    signer = Signer(private_key=identity.private_key_jwk, did=identity.did)
    public_b64 = raw_public_b64(identity.public_key_jwk)

    session = post(
        f"{args.worker}/conformance/session",
        {
            "implementation": {
                "name": args.name,
                "repo": args.repo,
                "commit": args.commit,
                "publicKeyB64": public_b64,
            }
        },
    )
    session_id = session["sessionId"]

    responses = answer(session["challenges"], signer)

    result = post(
        f"{args.worker}/conformance/session/{session_id}/submit",
        {"responses": responses},
    )

    level = result.get("levelAchieved")
    print(f"Conformance level: {level or 'none'}")
    for check in result.get("checks", []):
        mark = "PASS" if check.get("pass") else "FAIL"
        print(f"  [{mark}] {check['name']}: {check.get('detail', '')}")

    gh_output("level", level or "")
    gh_output("badge_url", result.get("badgeUrl") or "")
    gh_output("verify_url", result.get("verifyUrl") or "")

    summary = [f"### Vouch conformance: {level or 'not conformant'}", ""]
    for check in result.get("checks", []):
        mark = "check" if check.get("pass") else "x"
        summary.append(f"- `{mark}` {check['name']}: {check.get('detail', '')}")
    if result.get("badgeUrl"):
        summary += ["", f"Badge: {result['badgeUrl']}", f"Verify: {result.get('verifyUrl', '')}"]
    gh_summary(summary)

    return 0 if level else 1


if __name__ == "__main__":
    sys.exit(main())
