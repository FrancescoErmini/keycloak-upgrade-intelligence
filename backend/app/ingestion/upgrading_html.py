"""Parser of the official Keycloak *Upgrading Guide* HTML into a JSON catalog.

Structure of the page (Asciidoctor output, verified on the official sources):

    h2  Migration Changes                       (#migration-changes)
      h3  Migrating to 26.6.3                   (div.sect2)
        h4  Breaking changes                    (category header, div.sect3)
          h5  Valid redirect URIs ...           (entry, div.sect4)
            h6  ...                             (sub-sections, part of the entry)
        h4  Notable changes / Deprecated features / Removed features / End of Life features
      h3  Migrating to 26.0.0                   (older versions: no category headers,
        h4  Support for legacy redirect_uri ...  entries sit right under the version)

Asciidoctor ids of category headers are positional (`_breaking_changes_5`), so the
stable key of an entry is built from version + category + title, not from the id.
The table of contents (#toc) is parsed too and cross-checked against the body.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from bs4 import BeautifulSoup, Tag
from packaging.version import Version

from ..utils import stable_id

SCHEMA_VERSION = "1.0"
_MIGRATING = re.compile(r"^\s*Migrating to\s+(\d+\.\d+\.\d+)\s*$", re.I)
CATEGORY_HEADERS = {
    "breaking changes": "breaking",
    "notable changes": "notable",
    "deprecated features": "deprecated",
    "removed features": "removed",
    "end of life features": "end-of-life",
}
UNCATEGORIZED = "uncategorized"
HEADINGS = ("h2", "h3", "h4", "h5", "h6")


def _ws(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def heading_text(h: Tag) -> str:
    return _ws(h.get_text())


def slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")[:90]


def _level(h: Tag) -> int:
    return int(h.name[1])


def _section_blocks(h: Tag) -> list[Tag]:
    """Content blocks of the section opened by heading h (including nested sub-sections)."""
    parent = h.parent
    if isinstance(parent, Tag) and any(c.startswith("sect") for c in parent.get("class", [])):
        return [c for c in parent.children if isinstance(c, Tag) and c is not h]
    blocks = []  # fallback for non-Asciidoctor markup: siblings until a heading of same/higher level
    for sib in h.next_siblings:
        if not isinstance(sib, Tag):
            continue
        if sib.name in HEADINGS and _level(sib) <= _level(h):
            break
        blocks.append(sib)
    return blocks


def _block_text(block: Tag) -> tuple[list[str], list[str]]:
    """Return (paragraphs, code_blocks) for a block; nested sub-section headings become paragraphs."""
    paras, codes = [], []
    for el in block.find_all(["p", "pre", "li", "td", "h5", "h6", "dt"]) or [block]:
        if el.name == "pre":
            codes.append(el.get_text().strip())
            continue
        if el.name in ("li", "td", "dt") and el.find("p"):
            continue  # its <p> children are collected individually
        t = _ws(el.get_text())
        if t:
            paras.append(f"## {t}" if el.name in ("h5", "h6") else t)
    return paras, codes


def parse_toc(soup: BeautifulSoup) -> list[dict]:
    toc = soup.find(id="toc")
    if not toc:
        return []
    out = []
    for a in toc.find_all("a"):
        m = _MIGRATING.match(_ws(a.get_text()))
        if not m:
            continue
        li = a.find_parent("li")
        cats = []
        sub = li.find("ul") if li else None
        for ca in (sub.find_all("a", recursive=True) if sub else []):
            cats.append({"title": _ws(ca.get_text()), "anchor": ca.get("href", "").lstrip("#"),
                         "category": CATEGORY_HEADERS.get(_ws(ca.get_text()).lower())})
        out.append({"version": m.group(1), "anchor": a.get("href", "").lstrip("#"), "children": cats})
    return out


def parse_upgrading_html(html: str, source_url: str, fetched_at: str | None = None) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    headings = [h for h in soup.find_all(HEADINGS)]
    versions: list[dict] = []
    current: dict | None = None
    cat_level: int | None = None
    category = UNCATEGORIZED
    entry_level: int | None = None
    seen_ids: dict[str, int] = {}

    for h in headings:
        title = heading_text(h)
        m = _MIGRATING.match(title)
        if m:
            current = {"version": m.group(1), "anchor": h.get("id"), "level": _level(h), "categories": {}, "entries": []}
            versions.append(current)
            cat_level, category, entry_level = None, UNCATEGORIZED, None
            continue
        if current is None:
            continue
        lvl = _level(h)
        if lvl <= current["level"]:  # left the version (e.g. "Upgrading the Keycloak server")
            current = None
            continue
        cat = CATEGORY_HEADERS.get(title.lower())
        if cat and lvl == current["level"] + 1:
            cat_level, category, entry_level = lvl, cat, lvl + 1
            current["categories"][cat] = h.get("id")
            continue
        if entry_level is None:  # first heading under the version without a category header
            entry_level = current["level"] + 1
            category = UNCATEGORIZED
        if cat_level is not None and lvl == cat_level and not cat:
            category, entry_level = UNCATEGORIZED, lvl  # an entry at category level after categories
        if lvl != entry_level:
            continue  # deeper headings are part of the enclosing entry
        paras, codes = [], []
        for b in _section_blocks(h):
            p, c = _block_text(b)
            paras += p
            codes += c
        base = f"kc-{current['version']}-{category}-{slugify(title)}"
        seen_ids[base] = seen_ids.get(base, 0) + 1
        entry_id = base if seen_ids[base] == 1 else f"{base}-{seen_ids[base]}"
        text = "\n".join(paras)
        current["entries"].append({
            "entry_id": entry_id,
            "version": current["version"],
            "category": category,
            "title": title,
            "anchor": h.get("id"),
            "url": f"{source_url}#{h.get('id')}" if h.get("id") else source_url,
            "text": text,
            "code_blocks": codes,
            "links": sorted({a["href"] for b in _section_blocks(h) for a in b.find_all("a", href=True)
                             if a["href"].startswith("http")}),
            "content_hash": stable_id(title, text, codes, length=40),
        })

    # versions are listed newest first: "from" is the next lower version in the guide
    ordered = sorted(versions, key=lambda v: Version(v["version"]))
    prev = {v["version"]: (ordered[i - 1]["version"] if i else None) for i, v in enumerate(ordered)}
    entries = []
    for v in versions:
        v["from_version"], v["to_version"] = prev[v["version"]], v["version"]
        for e in v["entries"]:
            e["from_version"], e["to_version"] = v["from_version"], v["version"]
            entries.append(e)

    toc = parse_toc(soup)
    toc_versions = [t["version"] for t in toc]
    body_versions = [v["version"] for v in versions]
    warnings = []
    if toc and toc_versions != body_versions:
        warnings.append({"type": "toc-mismatch", "only_in_toc": sorted(set(toc_versions) - set(body_versions)),
                         "only_in_body": sorted(set(body_versions) - set(toc_versions))})
    for v in versions:
        if not v["entries"]:
            warnings.append({"type": "empty-version", "version": v["version"]})

    counts: dict[str, int] = {}
    for e in entries:
        counts[e["category"]] = counts.get(e["category"], 0) + 1
    return {
        "schema_version": SCHEMA_VERSION,
        "source_url": source_url,
        "fetched_at": fetched_at or datetime.now(timezone.utc).isoformat(),
        "content_sha256": stable_id(html, length=64),
        "stats": {"versions": len(versions), "entries": len(entries), "by_category": counts,
                  "toc_versions": len(toc_versions)},
        "warnings": warnings,
        "index": [{"version": v["version"], "from_version": v["from_version"], "to_version": v["to_version"],
                   "anchor": v["anchor"],
                   "categories": {c: sum(1 for e in v["entries"] if e["category"] == c)
                                  for c in dict.fromkeys(e["category"] for e in v["entries"])},
                   "entries": [e["entry_id"] for e in v["entries"]]} for v in versions],
        "entries": entries,
    }
