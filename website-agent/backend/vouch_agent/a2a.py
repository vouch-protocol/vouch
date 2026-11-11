"""A minimal A2A JSON-RPC 2.0 surface: ``message/send`` with text parts.

Parsing and response shapes only. The route in vouch_agent.main sends the
question through the same question-and-answer path as /chat.
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import Request

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

MAX_BODY_BYTES = 64 * 1024
# The same limit /chat applies to a question (ChatMessage.message).
MAX_TEXT_CHARS = 4000


class InvalidParams(ValueError):
    """The params of a message/send request are not a text message we accept."""


async def read_body(request: Request) -> bytes | None:
    """The request body, or None when it is larger than MAX_BODY_BYTES."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_BODY_BYTES:
        return None
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > MAX_BODY_BYTES:
            return None
    return bytes(body)


def is_request(req: Any) -> bool:
    return (
        isinstance(req, dict)
        and req.get("jsonrpc") == "2.0"
        and isinstance(req.get("method"), str)
        and isinstance(req.get("id"), (str, int))
        and not isinstance(req.get("id"), bool)
    )


def message_text(params: Any) -> tuple[str, str | None]:
    """The question text and contextId of a message/send request."""
    message = params.get("message") if isinstance(params, dict) else None
    if not isinstance(message, dict):
        raise InvalidParams("params.message is required")
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts:
        raise InvalidParams("message.parts must be a non-empty list")
    texts = []
    for part in parts:
        kind = part.get("kind", part.get("type")) if isinstance(part, dict) else None
        if kind != "text" or not isinstance(part.get("text"), str):
            raise InvalidParams("only text parts are accepted")
        texts.append(part["text"])
    text = "\n".join(texts).strip()
    if not text:
        raise InvalidParams("the message has no text")
    if len(text) > MAX_TEXT_CHARS:
        raise InvalidParams(f"the message is longer than {MAX_TEXT_CHARS} characters")
    context_id = message.get("contextId")
    return text, context_id if isinstance(context_id, str) else None


def agent_message(
    text: str, credential: dict[str, Any] | None, context_id: str | None
) -> dict[str, Any]:
    message: dict[str, Any] = {
        "kind": "message",
        "messageId": str(uuid.uuid4()),
        "role": "agent",
        "parts": [{"kind": "text", "text": text}],
        "contextId": context_id or str(uuid.uuid4()),
    }
    if credential is not None:
        message["metadata"] = {"vouchCredential": credential}
    return message


def result(req_id: Any, value: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": value}


def error(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
