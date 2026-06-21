from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Tuple

from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter

from aurora.rag.vector_store import get_vector_store, upsert_documents


@dataclass(frozen=True)
class RetrievalHit:
    source: str
    excerpt: str
    relevance_score: float | None


def _load_txt_files(paths: Iterable[Path]) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for p in paths:
        if not p.exists() or not p.is_file():
            continue
        if p.suffix.lower() not in {".txt", ".md"}:
            continue
        text = p.read_text(encoding="utf-8", errors="ignore")
        if text.strip():
            out.append((p.name, text))
    return out


def build_regulatory_index(data_root: Path, collection_name: str | None = None) -> int:
    circulars = list((data_root / "circulars").glob("**/*"))
    policies = list((data_root / "policies").glob("**/*"))

    raw = _load_txt_files([Path(x) for x in circulars + policies])
    if not raw:
        return 0

    splitter = RecursiveCharacterTextSplitter(chunk_size=900, chunk_overlap=120)

    docs: List[Document] = []
    for source_name, text in raw:
        chunks = splitter.split_text(text)
        for i, c in enumerate(chunks):
            docs.append(
                Document(
                    page_content=c,
                    metadata={"source": source_name, "chunk": i},
                )
            )

    return upsert_documents(docs, collection_name=collection_name)


def retrieve_clauses(query: str, k: int = 3, collection_name: str | None = None) -> List[RetrievalHit]:
    vs = get_vector_store(collection_name=collection_name)

    results: List[Tuple[Document, float]] = []
    try:
        results = vs.similarity_search_with_score(query, k=k)
    except Exception:
        docs = vs.similarity_search(query, k=k)
        results = [(d, None) for d in docs]

    hits: List[RetrievalHit] = []
    for doc, score in results:
        source = str(doc.metadata.get("source", "unknown"))
        hits.append(
            RetrievalHit(
                source=source,
                excerpt=doc.page_content,
                relevance_score=(float(score) if score is not None else None),
            )
        )
    return hits
