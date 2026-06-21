from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable, List

try:
    from langchain_chroma import Chroma  # type: ignore
except Exception:  # pragma: no cover
    from langchain_community.vectorstores import Chroma
from langchain_core.documents import Document

from aurora.rag.embeddings import get_embeddings


def _persist_dir() -> str:
    return os.getenv("CHROMA_PERSIST_DIR", "aurora/data/chroma")


def _default_collection_name() -> str:
    base = os.getenv("CHROMA_COLLECTION", "aurora-regulatory")
    embed = os.getenv("OLLAMA_EMBED_MODEL", "").strip()
    primary = (embed.split(",")[0].strip() if embed else "").lower()
    safe = "".join([c if c.isalnum() else "_" for c in primary])
    safe = safe.strip("_")
    if not safe:
        return base
    return f"{base}-{safe}"[:80]


def get_vector_store(collection_name: str | None = None) -> Chroma:
    collection_name = collection_name or _default_collection_name()
    return Chroma(
        collection_name=collection_name,
        persist_directory=_persist_dir(),
        embedding_function=get_embeddings(),
    )


def upsert_documents(docs: Iterable[Document], collection_name: str | None = None) -> int:
    vs = get_vector_store(collection_name=collection_name)
    docs_list: List[Document] = list(docs)
    if not docs_list:
        return 0
    vs.add_documents(docs_list)
    return len(docs_list)


def ensure_persist_dir() -> None:
    Path(_persist_dir()).mkdir(parents=True, exist_ok=True)
