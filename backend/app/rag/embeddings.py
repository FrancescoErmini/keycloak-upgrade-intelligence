"""Local embeddings.

Default backend is a deterministic feature-hashing embedder (no model download,
no network, reproducible in tests). If `EMBEDDING_BACKEND=sentence-transformers`
and the library is installed, a local transformer model is used instead.
"""
from __future__ import annotations

import hashlib
import math
import re
from functools import lru_cache

_TOKEN = re.compile(r"[a-z0-9_]+")
_STOP = {"the", "a", "an", "of", "to", "and", "or", "is", "are", "be", "in", "on", "for", "with", "that",
         "this", "as", "by", "it", "its", "such", "from", "now", "no", "longer", "must", "should", "which"}


class HashEmbedder:
    name = "hash-v1"

    def __init__(self, dim: int = 384) -> None:
        self.dim = dim

    @staticmethod
    def tokens(text: str) -> list[str]:
        toks = [t for t in _TOKEN.findall(text.lower()) if t not in _STOP]
        # light stemming so that "wildcards" ~ "wildcard", "rejected" ~ "reject"
        out = []
        for t in toks:
            for suf in ("ing", "ed", "es", "s"):
                if len(t) > 4 and t.endswith(suf):
                    t = t[: -len(suf)]
                    break
            out.append(t)
        return out

    def embed(self, text: str) -> list[float]:
        vec = [0.0] * self.dim
        toks = self.tokens(text)
        feats = toks + [f"{a}_{b}" for a, b in zip(toks, toks[1:])]
        for f in feats:
            h = hashlib.md5(f.encode()).digest()
            idx = int.from_bytes(h[:4], "little") % self.dim
            sign = 1.0 if h[4] & 1 else -1.0
            vec[idx] += sign * (1.0 if "_" not in f else 0.5)
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]


class SentenceTransformerEmbedder:
    def __init__(self, model: str) -> None:
        from sentence_transformers import SentenceTransformer  # optional dependency

        self.model = SentenceTransformer(model)
        self.name = model
        self.dim = self.model.get_sentence_embedding_dimension()

    def embed(self, text: str) -> list[float]:
        return [float(x) for x in self.model.encode(text, normalize_embeddings=True)]


@lru_cache(maxsize=4)
def get_embedder(backend: str = "hash", dim: int = 384, model: str = ""):
    if backend == "sentence-transformers":
        return SentenceTransformerEmbedder(model)
    return HashEmbedder(dim)
