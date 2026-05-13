"""Lightweight retrieval over the knowledge corpus.

Strategy: chunk the markdown files, build TF-IDF-ish term vectors,
score by cosine similarity. Good enough for a few thousand chunks and
avoids a hard dependency on a vector database.

For production-scale corpora, swap in a real embedding model (OpenAI
text-embedding-3-small or Voyage). The interface here returns a list
of (chunk_text, source_path, score) tuples so the LLM layer is agnostic.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from .config import CONFIG

_WORD_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]+")
_STOPWORDS = {
    "the", "a", "an", "is", "are", "be", "to", "of", "and", "or", "in", "on", "for",
    "with", "as", "by", "this", "that", "it", "its", "from", "at", "if", "you", "we",
    "i", "your", "my", "our", "but", "not", "do", "does", "can", "could", "should",
    "would", "have", "has", "had", "was", "were", "been", "will", "all", "any", "no",
}


@dataclass
class Chunk:
    text: str
    source: str
    vector: dict[str, float]
    norm: float


def _tokenize(text: str) -> list[str]:
    return [w.lower() for w in _WORD_RE.findall(text) if w.lower() not in _STOPWORDS]


def _chunk_markdown(text: str, max_chars: int, overlap: int) -> list[str]:
    chunks: list[str] = []
    cursor = 0
    while cursor < len(text):
        end = min(cursor + max_chars, len(text))
        if end < len(text):
            for boundary in ("\n## ", "\n### ", "\n\n", ". "):
                idx = text.rfind(boundary, cursor + max_chars // 2, end)
                if idx != -1:
                    end = idx + len(boundary)
                    break
        chunks.append(text[cursor:end].strip())
        if end == len(text):
            break
        cursor = max(end - overlap, cursor + 1)
    return [c for c in chunks if c]


class KnowledgeIndex:
    def __init__(self, knowledge_dir: Path, index_dir: Path) -> None:
        self.knowledge_dir = knowledge_dir
        self.index_dir = index_dir
        self.chunks: list[Chunk] = []
        self.idf: dict[str, float] = {}

    def fingerprint(self) -> str:
        h = hashlib.sha256()
        for path in sorted(self.knowledge_dir.glob("**/*.md")):
            h.update(path.name.encode())
            h.update(b"\0")
            h.update(path.read_bytes())
            h.update(b"\0")
        return h.hexdigest()[:16]

    def build(self) -> None:
        documents: list[tuple[str, str]] = []
        for path in sorted(self.knowledge_dir.glob("**/*.md")):
            for chunk_text in _chunk_markdown(path.read_text(encoding="utf-8"), CONFIG.chunk_chars, CONFIG.chunk_overlap):
                documents.append((chunk_text, str(path.relative_to(self.knowledge_dir))))
        df: Counter[str] = Counter()
        tokenized: list[tuple[str, str, list[str]]] = []
        for text, source in documents:
            tokens = _tokenize(text)
            tokenized.append((text, source, tokens))
            df.update(set(tokens))
        n_docs = max(len(documents), 1)
        self.idf = {term: math.log(1 + n_docs / (1 + df_count)) for term, df_count in df.items()}
        self.chunks = []
        for text, source, tokens in tokenized:
            tf = Counter(tokens)
            vector = {term: (count / max(len(tokens), 1)) * self.idf.get(term, 0.0) for term, count in tf.items()}
            norm = math.sqrt(sum(v * v for v in vector.values())) or 1.0
            self.chunks.append(Chunk(text=text, source=source, vector=vector, norm=norm))

    def save(self) -> None:
        self.index_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "fingerprint": self.fingerprint(),
            "idf": self.idf,
            "chunks": [
                {"text": c.text, "source": c.source, "vector": c.vector, "norm": c.norm} for c in self.chunks
            ],
        }
        (self.index_dir / "index.json").write_text(json.dumps(payload), encoding="utf-8")

    def load(self) -> bool:
        path = self.index_dir / "index.json"
        if not path.exists():
            return False
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("fingerprint") != self.fingerprint():
            return False
        self.idf = payload["idf"]
        self.chunks = [Chunk(**c) for c in payload["chunks"]]
        return True

    def search(self, query: str, top_k: int) -> list[tuple[Chunk, float]]:
        q_tokens = _tokenize(query)
        if not q_tokens:
            return []
        tf = Counter(q_tokens)
        q_vec = {term: (count / len(q_tokens)) * self.idf.get(term, 0.0) for term, count in tf.items()}
        q_norm = math.sqrt(sum(v * v for v in q_vec.values())) or 1.0
        scored: list[tuple[Chunk, float]] = []
        for chunk in self.chunks:
            dot = sum(q_vec.get(term, 0.0) * w for term, w in chunk.vector.items())
            sim = dot / (q_norm * chunk.norm)
            if sim > 0:
                scored.append((chunk, sim))
        scored.sort(key=lambda pair: pair[1], reverse=True)
        return scored[:top_k]


def get_index() -> KnowledgeIndex:
    index = KnowledgeIndex(CONFIG.knowledge_dir, CONFIG.index_dir)
    if not index.load():
        index.build()
        index.save()
    return index
