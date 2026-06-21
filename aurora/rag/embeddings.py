from __future__ import annotations

import os
from typing import List
from urllib.parse import urlparse

try:
    from langchain_ollama import OllamaEmbeddings  # type: ignore
except Exception:  # pragma: no cover
    from langchain_community.embeddings import OllamaEmbeddings
from langchain_community.embeddings.fake import FakeEmbeddings
from langchain_core.embeddings import Embeddings


class ResilientEmbeddings(Embeddings):
    def __init__(self, *, base_url: str, models: List[str]):
        self._base_url = base_url
        self._models = [m for m in (models or []) if m]
        self._active_idx = 0
        self._ollama: OllamaEmbeddings | None = None
        self._fake: FakeEmbeddings | None = None

    def _is_missing_model_error(self, e: Exception) -> bool:
        msg = str(e)
        return "status code: 404" in msg.lower() or "model" in msg.lower() and "not found" in msg.lower()

    def _ensure_backend(self) -> Embeddings:
        if self._ollama is not None:
            return self._ollama
        if self._fake is not None:
            return self._fake

        if not self._models:
            self._fake = FakeEmbeddings(size=768)
            return self._fake

        model = self._models[self._active_idx]
        self._ollama = OllamaEmbeddings(base_url=self._base_url, model=model)
        return self._ollama

    def _rotate_model(self) -> bool:
        self._ollama = None
        if self._active_idx + 1 < len(self._models):
            self._active_idx += 1
            return True
        self._fake = FakeEmbeddings(size=768)
        return False

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        while True:
            backend = self._ensure_backend()
            try:
                return backend.embed_documents(texts)
            except Exception as e:
                if backend is self._fake or not self._is_missing_model_error(e):
                    raise
                if not self._rotate_model():
                    return self._fake.embed_documents(texts)  # type: ignore[union-attr]

    def embed_query(self, text: str) -> List[float]:
        while True:
            backend = self._ensure_backend()
            try:
                return backend.embed_query(text)
            except Exception as e:
                if backend is self._fake or not self._is_missing_model_error(e):
                    raise
                if not self._rotate_model():
                    return self._fake.embed_query(text)  # type: ignore[union-attr]


def get_embeddings() -> Embeddings:
    raw = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        p = urlparse(raw)
        base_url = f"{p.scheme}://{p.netloc}" if p.scheme and p.netloc else raw
    except Exception:
        base_url = raw
    raw = os.getenv("OLLAMA_EMBED_MODEL", "granite-embedding:30m-en,granite-embedding:30m")
    models = [m.strip() for m in raw.split(",") if m.strip()]
    return ResilientEmbeddings(base_url=base_url, models=models)
