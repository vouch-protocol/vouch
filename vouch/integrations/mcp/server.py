"""
Vouch Protocol MCP Server - Model Context Protocol integration.

A Standard-IO (stdio) JSON-RPC MCP server for Claude Desktop, Cursor, and any
MCP-compatible client. It exposes the full Vouch capability surface as tools so
any agent can give itself a verifiable identity, sign and verify credentials,
check for leaked keys, and decode DIDs, with no extra setup.

Two classes of tools:
  - Open tools (no key needed): create_identity, verify_credential,
    verify_token, scan, decode_did. These let any client verify and inspect
    without configuring a signing identity.
  - Signing tools (need VOUCH_PRIVATE_KEY and VOUCH_DID in the environment):
    sign_credential, sign_action, create_session, get_identity, get_public_key.

Every handler is wrapped so a bad input returns a clean JSON-RPC error instead
of crashing the server loop.
"""

import base64
import json
import logging
import os
import sys
import time
from typing import Any, Dict, List, Optional

from vouch import Signer, Verifier, generate_identity

logging.basicConfig(level=logging.INFO, stream=sys.stderr)
logger = logging.getLogger(__name__)

SERVER_VERSION = "2.0.0"
PROTOCOL_VERSION = "2024-11-05"


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _did_key_from_public_jwk(public_key_jwk: str) -> Optional[str]:
    """Derive a did:key from an Ed25519 public JWK, offline. Returns None on failure."""
    try:
        from vouch.multikey import encode_ed25519_public

        jwk = json.loads(public_key_jwk)
        raw = _b64url_decode(jwk["x"])
        return "did:key:" + encode_ed25519_public(raw)
    except Exception as exc:  # noqa: BLE001
        logger.warning("did:key derivation failed: %s", exc)
        return None


class VouchMCPServer:
    """MCP server exposing the full Vouch capability surface."""

    def __init__(self) -> None:
        self._signer: Optional[Signer] = None
        self._did: Optional[str] = None
        self._auto_sign = os.getenv("VOUCH_AUTO_SIGN", "").lower() in ("true", "1", "yes")
        self._session_token: Optional[str] = None
        self._load_credentials()

    # -- credential loading ------------------------------------------------
    def _load_credentials(self) -> None:
        private_key = os.getenv("VOUCH_PRIVATE_KEY")
        did = os.getenv("VOUCH_DID")
        if private_key and did:
            try:
                self._signer = Signer(private_key=private_key, did=did)
                self._did = did
                mode = "(auto-sign on)" if self._auto_sign else ""
                logger.info("Vouch MCP server ready, DID: %s %s", did, mode)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to initialize signer: %s", exc)
        else:
            logger.info("No signing identity configured. Open tools still work.")

    # -- tool catalog ------------------------------------------------------
    def _get_tools_list(self) -> List[Dict[str, Any]]:
        return [
            {
                "name": "create_identity",
                "description": "Create a new verifiable agent identity (a DID plus keypair). Use a domain for did:web, or omit it for a portable did:key. Returns the DID and keys; store the private key securely.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "domain": {"type": "string", "description": "Optional domain for did:web, e.g. agent.acme.com. Omit for did:key."}
                    },
                },
            },
            {
                "name": "sign_credential",
                "description": "Sign a verifiable Vouch credential for an action. Requires a configured signing identity. action, target, and resource are required; resource is the concrete URL the action touches (prevents confused-deputy attacks).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "The action, e.g. read, refund, deploy."},
                        "target": {"type": "string", "description": "What the action is about, e.g. order:1042."},
                        "resource": {"type": "string", "description": "The concrete resource URL the action touches."},
                        "reputation_score": {"type": "integer", "description": "Optional reputation score 0-100."},
                        "valid_seconds": {"type": "integer", "description": "Optional validity window in seconds (default 300)."},
                        "hybrid": {"type": "boolean", "description": "If true, also attach a post-quantum (ML-DSA-44) proof."},
                        "parent_credential": {"type": "object", "description": "Optional parent credential to delegate from (builds a delegation chain)."},
                    },
                    "required": ["action", "target", "resource"],
                },
            },
            {
                "name": "create_delegated_identity",
                "description": "Mint a short-lived, self-cleaning identity for a spawned sub-agent. Uses the configured signer as the parent and issues the child a fresh did:key plus a time-bound delegated credential scoped to action/target/resource. The credential auto-expires after ttl_seconds (nothing to clean up). Requires a configured signing identity. Returns the child did:key, its keys, and the delegation credential.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "description": "The action the sub-agent may take, e.g. read, summarize, deploy."},
                        "target": {"type": "string", "description": "What the action is about, e.g. repo:vouch-protocol."},
                        "resource": {"type": "string", "description": "The concrete resource URL the action touches."},
                        "ttl_seconds": {"type": "integer", "description": "How long the child credential stays valid, in seconds. After this it is rejected on its temporal check."},
                        "reputation_score": {"type": "integer", "description": "Optional reputation score 0-100 to carry on the child credential."},
                    },
                    "required": ["action", "target", "resource", "ttl_seconds"],
                },
            },
            {
                "name": "verify_credential",
                "description": "Verify a Vouch credential. Returns whether it is valid and, if so, who issued it, the action, and the validity window. Provide public_key (JWK) for offline verification of did:web/did:key identities.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "credential": {"type": "object", "description": "The credential to verify (object or JSON string)."},
                        "public_key": {"type": "string", "description": "Optional public key JWK to verify against."},
                    },
                    "required": ["credential"],
                },
            },
            {
                "name": "verify_token",
                "description": "Verify a legacy Vouch JWS token. Returns validity and the issuer, subject, and payload.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "token": {"type": "string", "description": "The JWS token to verify."},
                        "public_key_jwk": {"type": "string", "description": "Optional public key JWK to verify against."},
                    },
                    "required": ["token"],
                },
            },
            {
                "name": "scan",
                "description": "Scan text or a filesystem path for leaked Vouch-shaped private key material (private JWKs, seeds, DID documents with private keys). Returns findings with severity. Pass either content or path.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": {"type": "string", "description": "Inline text to scan."},
                        "path": {"type": "string", "description": "A file or directory path to scan."},
                    },
                },
            },
            {
                "name": "decode_did",
                "description": "Decode or resolve a DID. For did:key, returns the algorithm and key offline. For did:web, attempts to resolve the DID Document over HTTPS (needs network).",
                "inputSchema": {
                    "type": "object",
                    "properties": {"did": {"type": "string", "description": "The DID to decode or resolve."}},
                    "required": ["did"],
                },
            },
            {
                "name": "get_identity",
                "description": "Get the configured agent's DID and signing status.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "get_public_key",
                "description": "Export the configured agent's public key (JWK and Multikey), verification method id, and a ready-to-publish DID Document. Requires a configured identity.",
                "inputSchema": {"type": "object", "properties": {}},
            },
            {
                "name": "sign_action",
                "description": "Legacy: sign a simple action as a Vouch-Token (JWS) for an authenticated API call. Prefer sign_credential for new work.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "intent": {"type": "string", "description": "What action are you taking?"},
                        "target": {"type": "string", "description": "Optional target service or resource."},
                    },
                    "required": ["intent"],
                },
            },
            {
                "name": "create_session",
                "description": "Legacy: create a session token valid for multiple actions for one hour. Requires a configured identity.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"purpose": {"type": "string", "description": "What is this session for?"}},
                    "required": ["purpose"],
                },
            },
        ]

    # -- request routing ---------------------------------------------------
    def process_request(self, line: str) -> Optional[Dict[str, Any]]:
        try:
            request = json.loads(line.strip())
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON: %s", exc)
            return None

        request_id = request.get("id")
        method = request.get("method")

        if method == "initialize":
            return self._result(request_id, None, raw_result={
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "vouch-mcp-server", "version": SERVER_VERSION},
            })
        if method == "tools/list":
            return self._result(request_id, None, raw_result={"tools": self._get_tools_list()})
        if method == "tools/call":
            params = request.get("params", {})
            return self._handle_tool_call(request_id, params.get("name"), params.get("arguments", {}) or {})
        if method in ("notifications/initialized", "initialized"):
            return None
        return self._error(request_id, -32601, f"Method not found: {method}")

    def _handle_tool_call(self, request_id: Any, tool: str, args: Dict[str, Any]) -> Dict[str, Any]:
        handlers = {
            "create_identity": self._t_create_identity,
            "create_delegated_identity": self._t_create_delegated_identity,
            "sign_credential": self._t_sign_credential,
            "verify_credential": self._t_verify_credential,
            "verify_token": self._t_verify_token,
            "scan": self._t_scan,
            "decode_did": self._t_decode_did,
            "get_identity": self._t_get_identity,
            "get_public_key": self._t_get_public_key,
            "sign_action": self._t_sign_action,
            "create_session": self._t_create_session,
        }
        handler = handlers.get(tool)
        if handler is None:
            return self._error(request_id, -32602, f"Unknown tool: {tool}")
        try:
            return self._result(request_id, handler(args))
        except _ToolError as exc:
            return self._error(request_id, -32603, str(exc))
        except Exception as exc:  # noqa: BLE001
            logger.error("Tool %s failed: %s", tool, exc)
            return self._error(request_id, -32603, f"{tool} failed: {exc}")

    # -- tool handlers -----------------------------------------------------
    def _t_create_identity(self, args: Dict[str, Any]) -> str:
        domain = args.get("domain")
        keypair = generate_identity(domain=domain) if domain else generate_identity()
        did = keypair.did or _did_key_from_public_jwk(keypair.public_key_jwk) or "(no DID; provide a domain for did:web)"
        return (
            f"New Vouch identity created.\n"
            f"DID: {did}\n\n"
            f"Public key (JWK):\n{keypair.public_key_jwk}\n\n"
            f"Private key (JWK) - store securely, never commit or share:\n{keypair.private_key_jwk}\n\n"
            f"Set VOUCH_DID and VOUCH_PRIVATE_KEY to use this identity for signing."
        )

    def _t_create_delegated_identity(self, args: Dict[str, Any]) -> str:
        from vouch.ephemeral import spawn_ephemeral_identity

        parent = self._require_signer()
        intent = {
            "action": args["action"],
            "target": args["target"],
            "resource": args["resource"],
        }
        ttl_seconds = int(args["ttl_seconds"])
        rep = args.get("reputation_score")
        identity = spawn_ephemeral_identity(
            parent,
            intent,
            ttl_seconds,
            reputation_score=int(rep) if rep is not None else None,
        )
        return (
            f"Ephemeral sub-agent identity created by {parent.get_did()}.\n"
            f"Child DID (did:key, self-contained, nothing to host): {identity.did}\n"
            f"Scope: action={intent['action']}, target={intent['target']}, resource={intent['resource']}\n"
            f"Valid until (auto-expires, nothing to clean up): {identity.valid_until}\n\n"
            f"Child private key (JWK) - hand to the sub-agent, never log or persist:\n"
            f"{identity.private_key_jwk}\n\n"
            f"Delegation credential:\n"
            + json.dumps(identity.credential, indent=2)
        )

    def _t_sign_credential(self, args: Dict[str, Any]) -> str:
        signer = self._require_signer()
        intent = {
            "action": args["action"],
            "target": args["target"],
            "resource": args["resource"],
        }
        kwargs: Dict[str, Any] = {}
        if args.get("reputation_score") is not None:
            kwargs["reputation_score"] = int(args["reputation_score"])
        if args.get("valid_seconds") is not None:
            kwargs["valid_seconds"] = int(args["valid_seconds"])
        if args.get("parent_credential"):
            kwargs["parent_credential"] = args["parent_credential"]
        if args.get("hybrid"):
            credential = signer.sign_credential_hybrid(intent=intent, **kwargs)
        else:
            credential = signer.sign_credential(intent=intent, **kwargs)
        return "Signed Vouch credential:\n" + json.dumps(credential, indent=2)

    def _t_verify_credential(self, args: Dict[str, Any]) -> str:
        credential = self._as_object(args.get("credential"), "credential")
        public_key = args.get("public_key")
        is_valid, passport = Verifier.verify_credential(credential, public_key=public_key)
        if not is_valid or passport is None:
            return "Verification result: REJECTED. The credential is not valid (bad signature, tampering, or expiry)."
        intent = passport.intent or {}
        return (
            "Verification result: ACCEPTED.\n"
            f"issuer:     {passport.iss}\n"
            f"subject:    {passport.sub}\n"
            f"action:     {intent.get('action')}\n"
            f"target:     {intent.get('target')}\n"
            f"resource:   {intent.get('resource')}\n"
            f"valid_from: {passport.valid_from}\n"
            f"valid_until:{passport.valid_until}"
        )

    def _t_verify_token(self, args: Dict[str, Any]) -> str:
        token = args["token"]
        is_valid, passport = Verifier.verify(token, public_key_jwk=args.get("public_key_jwk"))
        if not is_valid or passport is None:
            return "Verification result: REJECTED. The token is not valid."
        return (
            "Verification result: ACCEPTED.\n"
            f"issuer:  {passport.iss}\n"
            f"subject: {passport.sub}\n"
            f"payload: {json.dumps(passport.payload)}"
        )

    def _t_scan(self, args: Dict[str, Any]) -> str:
        from vouch.scan import scan_path, scan_text
        from vouch.scan.detector import findings_to_json

        content = args.get("content")
        path = args.get("path")
        if content is not None:
            findings = scan_text(content, file_label="<mcp-input>")
        elif path:
            findings = scan_path(path)
        else:
            raise _ToolError("Provide either 'content' or 'path' to scan.")
        if not findings:
            return "Scan complete. No leaked Vouch key material detected."
        return f"Scan complete. {len(findings)} finding(s):\n" + findings_to_json(findings)

    def _t_decode_did(self, args: Dict[str, Any]) -> str:
        did = args["did"]
        if did.startswith("did:key:"):
            from vouch.multikey import algorithm_of

            multikey = did[len("did:key:"):]
            algorithm = algorithm_of(multikey)
            return f"did:key decoded.\nalgorithm: {algorithm}\nmultikey:  {multikey}"
        if did.startswith("did:web:"):
            try:
                from vouch.did_web import resolve_did_web_sync

                doc = resolve_did_web_sync(did)
                multibase = doc.get_public_key_multibase()
                return f"did:web resolved.\nDID: {did}\npublicKeyMultibase: {multibase}"
            except Exception as exc:  # noqa: BLE001
                raise _ToolError(f"Could not resolve {did} (needs network and a published DID Document): {exc}")
        raise _ToolError(f"Unsupported DID method for: {did}")

    def _t_get_identity(self, _args: Dict[str, Any]) -> str:
        return (
            f"Agent DID: {self._did or 'not configured'}\n"
            f"Auto-sign: {'on' if self._auto_sign else 'off'}\n"
            f"Session:   {'active' if self._session_token else 'none'}"
        )

    def _t_get_public_key(self, _args: Dict[str, Any]) -> str:
        signer = self._require_signer()
        jwk = signer.get_public_key_jwk()
        multikey = signer.get_public_key_multikey()
        vm_id = signer.verification_method_id()
        did_document = {
            "@context": "https://www.w3.org/ns/did/v1",
            "id": self._did,
            "verificationMethod": [
                {"id": vm_id, "type": "Multikey", "controller": self._did, "publicKeyMultibase": multikey}
            ],
            "authentication": [vm_id],
            "assertionMethod": [vm_id],
        }
        return (
            f"public_key_jwk: {jwk}\n"
            f"public_key_multikey: {multikey}\n"
            f"verification_method: {vm_id}\n\n"
            f"DID Document (publish at https://<domain>/.well-known/did.json):\n"
            + json.dumps(did_document, indent=2)
        )

    def _t_sign_action(self, args: Dict[str, Any]) -> str:
        signer = self._require_signer()
        payload: Dict[str, Any] = {"intent": args["intent"]}
        if args.get("target"):
            payload["target"] = args["target"]
        token = signer.sign(payload)
        return f"Vouch-Token: {token}\n\nSend it as a header: 'Vouch-Token: {token}'"

    def _t_create_session(self, args: Dict[str, Any]) -> str:
        signer = self._require_signer()
        purpose = args.get("purpose", "general")
        payload = {"type": "session", "purpose": purpose, "created_at": int(time.time()), "valid_for": "1 hour"}
        self._session_token = signer.sign(payload)
        return f"Session created for: {purpose}\nSession-Token: {self._session_token}"

    # -- helpers -----------------------------------------------------------
    def _require_signer(self) -> Signer:
        if self._signer is None:
            raise _ToolError("No signing identity configured. Set VOUCH_PRIVATE_KEY and VOUCH_DID, or call create_identity first.")
        return self._signer

    @staticmethod
    def _as_object(value: Any, name: str) -> Dict[str, Any]:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                return json.loads(value)
            except json.JSONDecodeError as exc:
                raise _ToolError(f"{name} is not valid JSON: {exc}")
        raise _ToolError(f"{name} must be an object or a JSON string.")

    @staticmethod
    def _result(request_id: Any, text: Optional[str], raw_result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if raw_result is not None:
            return {"jsonrpc": "2.0", "id": request_id, "result": raw_result}
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {"content": [{"type": "text", "text": text or ""}]},
        }

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> Dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    # -- loop --------------------------------------------------------------
    def run(self) -> None:
        logger.info("Vouch MCP server starting (v%s)", SERVER_VERSION)
        for line in sys.stdin:
            if not line.strip():
                continue
            response = self.process_request(line)
            if response is not None:
                print(json.dumps(response), flush=True)


class _ToolError(Exception):
    """A clean, user-facing tool error."""


def main() -> None:
    VouchMCPServer().run()


if __name__ == "__main__":
    main()
