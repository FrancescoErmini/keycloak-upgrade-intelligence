"""Small shared helpers: stable identifiers, dotted-path access, version ranges."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import InvalidVersion, Version

_MISSING = object()


def stable_id(*parts: Any, length: int = 20) -> str:
    """Deterministic identifier: re-running a pipeline on the same input yields the same ids."""
    raw = "\x1f".join(json.dumps(p, sort_keys=True, default=str) if not isinstance(p, str) else p for p in parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:length]


def get_path(doc: Any, path: str, default: Any = None) -> Any:
    """Resolve 'a.b.c' in nested dicts, also accepting flattened ECS keys such as {'log.logger': ...}."""
    if not isinstance(doc, dict):
        return default
    if path in doc:
        return doc[path]
    head, _, tail = path.partition(".")
    if tail and head in doc:
        return get_path(doc[head], tail, default)
    # flattened prefix e.g. {"log.logger": ...} looked up as "log.logger" handled above;
    # mixed form e.g. {"http.request": {"method": ...}}
    parts = path.split(".")
    for i in range(len(parts) - 1, 0, -1):
        key = ".".join(parts[:i])
        if key in doc:
            return get_path(doc[key], ".".join(parts[i:]), default)
    return default


def parse_version(v: str | None) -> Version | None:
    if not v:
        return None
    try:
        return Version(str(v))
    except InvalidVersion:
        return None


def is_applicable(introduced_in: str | None, source: str, target: str) -> bool:
    """A breaking change applies when source < introduced_in <= target."""
    intro = parse_version(introduced_in)
    if intro is None:
        return True  # controls / version-less rules always apply
    return Version(source) < intro <= Version(target)


def version_matches(version: str, spec: str) -> bool:
    return Version(version) in SpecifierSet(spec.replace(" ", ""), prereleases=True)
