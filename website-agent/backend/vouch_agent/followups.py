"""Follow-up question extraction and fallback bank.

The LLM is instructed (by llm.py's system prompt) to end every substantive
answer with a literal `---FOLLOWUPS---` marker followed by three bullets.
That contract is fragile in practice: the model may forget the marker,
emit `*` or `•` instead of `-`, number them, or split the marker across
tokens. The backend treats its own output as untrusted and re-extracts
the list with tolerant regexes here, then falls back to a per-source
question bank when nothing usable came back.

Public surface:
- `FOLLOWUPS_MARKER`         marker emitted by the LLM
- `extract_followups(text)`  -> (questions, body_without_followups)
- `is_substantive(text)`     heuristic for "worth suggesting at all"
- `fallback_followups(sources)` 3 generic questions keyed off top source
"""

from __future__ import annotations

import re
from typing import Iterable

FOLLOWUPS_MARKER = "---FOLLOWUPS---"

# Per-source-file fallback follow-ups. Keys are matched as suffixes against
# `sources[i]["source"]` (case-insensitive), so "quickstart.md" matches a
# corpus entry like "docs/quickstart.md" too.
_SOURCE_FOLLOWUPS: dict[str, list[str]] = {
    "quickstart.md": [
        "How do I sign my first Vouch credential in Python?",
        "What does a real signed credential look like on the wire?",
        "How does the verifier reject a tampered credential?",
    ],
    "verifier.md": [
        "What's the most common reason verification fails in practice?",
        "How do I write integration tests for the verifier?",
        "Can I cache resolved DIDs safely, and for how long?",
    ],
    "conformance.md": [
        "What's the difference between L1, L2, and L3 conformance?",
        "Which level does the reference implementation meet today?",
        "How do I certify my own implementation against L2?",
    ],
    "delegation.md": [
        "How deep can a delegation chain go before verification slows down?",
        "What happens if a parent's DID is revoked mid-chain?",
        "How do I narrow scope when delegating to a sub-agent?",
    ],
    "post-quantum.md": [
        "How do I enable hybrid post-quantum proofs?",
        "Does PQ mode break compatibility with classical verifiers?",
        "What's the size overhead of an ML-DSA proof in practice?",
    ],
    "compliance.md": [
        "Which GDPR articles does a Vouch credential help satisfy?",
        "How does Vouch map to the EU AI Act transparency duties?",
        "What HIPAA controls can Vouch evidence support?",
    ],
    "sdk-python.md": [
        "How do I rotate signing keys without breaking outstanding credentials?",
        "What's the recommended way to embed Vouch in a FastAPI handler?",
        "Can I sign batch credentials and verify them in parallel?",
    ],
    "sdk-ts.md": [
        "How do I use Vouch from a Next.js Route Handler?",
        "Does the TypeScript SDK work in Cloudflare Workers?",
        "How do I share signing logic between Node and edge runtimes?",
    ],
}

# Used when no source-keyed bank matches.
_DEFAULT_FOLLOWUPS: list[str] = [
    "How do I sign my first Vouch credential in Python?",
    "What does the wire format of a Vouch credential look like?",
    "How does the verifier reject a tampered credential?",
]

# Tolerant bullet patterns: `-`, `*`, `•`, em-dash, or "1." / "1)".
_BULLET_RE = re.compile(r"^\s*(?:[-*•–—]|\d+[.)])\s+(.+?)\s*$")

# Defensive: a short answer or an obvious refusal does not deserve chips.
_MIN_SUBSTANTIVE_CHARS = 180


def extract_followups(full_text: str) -> tuple[list[str], str]:
    """Pull follow-up questions out of `full_text`.

    Returns (questions, body_without_followups). If no marker is present,
    the body equals the input and `questions` is empty. Questions are
    canonicalised: stripped, bullet removed, trailing `?` enforced,
    length-clamped to 6..200 chars, deduped, capped at 3.
    """
    idx = full_text.find(FOLLOWUPS_MARKER)
    if idx == -1:
        return [], full_text
    head = full_text[:idx].rstrip()
    tail = full_text[idx + len(FOLLOWUPS_MARKER):]
    seen: set[str] = set()
    questions: list[str] = []
    for raw_line in tail.splitlines():
        m = _BULLET_RE.match(raw_line)
        if not m:
            continue
        q = m.group(1).strip()
        # Trim a single trailing `?` to normalise, then re-add.
        while q.endswith("?"):
            q = q[:-1].rstrip()
        if not q:
            continue
        q = q + "?"
        if not (6 <= len(q) <= 200):
            continue
        key = q.lower()
        if key in seen:
            continue
        seen.add(key)
        questions.append(q)
        if len(questions) >= 3:
            break
    return questions, head


def is_substantive(body: str) -> bool:
    """Cheap heuristic: only suggest follow-ups when the answer went somewhere.

    Short greetings / refusals fall under the threshold. We deliberately do
    NOT check for citations or code: a long prose answer about, say,
    delegation depth is still worth suggesting follow-ups on even if it
    cited nothing.
    """
    return len(body.strip()) >= _MIN_SUBSTANTIVE_CHARS


def fallback_followups(sources: Iterable[dict] | None) -> list[str]:
    """Pick 3 generic follow-ups based on the highest-scoring RAG source.

    `sources` is the list the backend already emits in the `meta` event:
    [{"source": "quickstart.md", "score": 0.42}, ...]. We match by case-
    insensitive suffix so corpus entries like "docs/quickstart.md" still
    hit the "quickstart.md" bank.
    """
    if sources:
        for src in sources:
            name = str(src.get("source", "")).lower()
            if not name:
                continue
            for key, qs in _SOURCE_FOLLOWUPS.items():
                if name.endswith(key.lower()):
                    return list(qs)
    return list(_DEFAULT_FOLLOWUPS)
