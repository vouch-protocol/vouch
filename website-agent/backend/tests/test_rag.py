"""Smoke tests for the RAG layer."""

from __future__ import annotations

from pathlib import Path

import pytest

from vouch_agent.rag import KnowledgeIndex


@pytest.fixture()
def knowledge_dir(tmp_path: Path) -> Path:
    (tmp_path / "a.md").write_text(
        "# Vouch overview\n\nVouch is a protocol for AI agent identity. "
        "Agents have DIDs and sign actions with Ed25519.",
        encoding="utf-8",
    )
    (tmp_path / "b.md").write_text(
        "# Revocation\n\nThe issuer publishes a BitstringStatusList. The verifier checks the bit.",
        encoding="utf-8",
    )
    return tmp_path


def test_index_builds_and_searches(knowledge_dir: Path, tmp_path: Path) -> None:
    index = KnowledgeIndex(knowledge_dir, tmp_path / "index")
    index.build()
    assert len(index.chunks) >= 2
    hits = index.search("how does revocation work", top_k=2)
    assert hits
    top_source, _ = hits[0]
    assert "revocation" in top_source.source.lower() or "bitstring" in top_source.text.lower()


def test_index_persists(knowledge_dir: Path, tmp_path: Path) -> None:
    idx1 = KnowledgeIndex(knowledge_dir, tmp_path / "index")
    idx1.build()
    idx1.save()
    idx2 = KnowledgeIndex(knowledge_dir, tmp_path / "index")
    assert idx2.load()
    assert len(idx2.chunks) == len(idx1.chunks)


def test_fingerprint_invalidates_on_change(knowledge_dir: Path, tmp_path: Path) -> None:
    idx1 = KnowledgeIndex(knowledge_dir, tmp_path / "index")
    idx1.build()
    idx1.save()

    (knowledge_dir / "a.md").write_text("# different content", encoding="utf-8")

    idx2 = KnowledgeIndex(knowledge_dir, tmp_path / "index")
    assert not idx2.load()
