"""Manual sync job for the Keycloak Upgrading Guide.

    python -m app.jobs.sync_breaking_changes                     # download, parse, LLM, index
    python -m app.jobs.sync_breaking_changes --no-llm            # only refresh catalog + index
    python -m app.jobs.sync_breaking_changes --file page.html    # use a saved HTML page
    docker compose --profile jobs run --rm bc-sync               # same, inside the stack

Steps
  1. fetch   the official HTML (BC_SOURCE_URL) and store it in data/breaking-changes/source/
  2. parse   HTML -> data/breaking-changes/catalog.json (index by version from/to, categories, entries)
  3. diff    against the previous catalog (added / changed / removed entries)
  4. map     eligible entries onto the detector registry with the LLM (cached per entry hash)
             -> data/breaking-changes/rules/llm-candidates.json (status candidate / rejected / not-detectable)
  5. report  data/breaking-changes/sync-report.json (stats, diff, shared filters, detector proposals)
  6. index   catalog + rules into Elasticsearch (Pipeline A), unless --no-index
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import requests

from ..config import get_settings
from ..ingestion.breaking_changes import bc_dir, ingest_breaking_changes, load_approved, load_json
from ..ingestion.rule_extraction import extract_rules
from ..ingestion.upgrading_html import parse_upgrading_html
from ..llm.providers import NoLLM, get_provider
from ..store import build_store

USER_AGENT = "kc-upgrade-analyzer-sync/0.2 (+https://github.com/)"


def fetch(url: str) -> str:
    r = requests.get(url, timeout=60, headers={"User-Agent": USER_AGENT, "Accept": "text/html"})
    r.raise_for_status()
    r.encoding = r.encoding or "utf-8"
    return r.text


def diff_catalogs(old: dict | None, new: dict) -> dict:
    if not old:
        return {"first_sync": True, "added": len(new["entries"]), "changed": 0, "removed": 0}
    o = {e["entry_id"]: e["content_hash"] for e in old["entries"]}
    n = {e["entry_id"]: e["content_hash"] for e in new["entries"]}
    return {
        "first_sync": False,
        "previous_fetched_at": old.get("fetched_at"),
        "added": sorted(set(n) - set(o)),
        "changed": sorted(k for k in set(n) & set(o) if n[k] != o[k]),
        "removed": sorted(set(o) - set(n)),
        "new_versions": sorted({e["version"] for e in new["entries"]} - {e["version"] for e in old["entries"]}),
    }


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(args: argparse.Namespace) -> dict:
    settings = get_settings()
    if args.data_dir:
        settings = replace(settings, data_dir=Path(args.data_dir))
    base = bc_dir(settings.data_dir)
    now = datetime.now(timezone.utc).isoformat()

    # 1. fetch
    url = args.url or settings.bc_source_url
    if args.file:
        html, origin = Path(args.file).read_text(encoding="utf-8"), f"file:{args.file}"
    else:
        html, origin = fetch(url), url
    if not args.dry_run:
        (base / "source").mkdir(parents=True, exist_ok=True)
        (base / "source" / "upgrading-guide.html").write_text(html, encoding="utf-8")
        write_json(base / "source" / "meta.json", {"retrieved_from": origin, "retrieved_at": now, "source_url": url})

    # 2. parse
    catalog = parse_upgrading_html(html, url, now)
    catalog["retrieved_from"] = origin
    if catalog["stats"]["entries"] == 0:
        raise SystemExit("no entries parsed: the page layout changed, check the HTML (nothing was written)")

    # 3. diff
    previous = load_json(base / "catalog.json")
    diff = diff_catalogs(previous, catalog)

    # 4. LLM mapping
    llm = NoLLM() if (args.no_llm or args.dry_run) else get_provider(settings)
    prev_candidates = load_json(base / "rules" / "llm-candidates.json", {"candidates": {}})["candidates"]
    approved = load_approved(settings.data_dir)["rules"]
    if llm.available():
        candidates, llm_report = extract_rules(
            catalog, llm, approved, prev_candidates,
            min_version=args.min_version or settings.bc_min_version,
            categories=tuple(args.categories.split(",")) if args.categories else settings.bc_llm_categories,
            force=args.force_llm, max_entries=args.max_entries)
    else:
        candidates = {k: v for k, v in prev_candidates.items()
                      if k in {e["entry_id"] for e in catalog["entries"]}}  # keep reviewed work, drop vanished entries
        llm_report = {"stats": {"skipped": "LLM disabled or not configured (LLM_PROVIDER / OPENAI_API_KEY)"}}

    report = {"synced_at": now, "source": origin, "catalog": catalog["stats"], "parse_warnings": catalog["warnings"],
              "diff": diff, "llm": {"provider": llm.name, "model": getattr(llm, "model", None), **llm_report}}
    if args.dry_run:
        return report

    write_json(base / "catalog.json", catalog)
    write_json(base / "rules" / "llm-candidates.json", {"schema_version": "2.0", "updated_at": now, "candidates": candidates})
    write_json(base / "sync-report.json", report)

    # 6. index
    if not args.no_index:
        store = build_store(settings)
        store.ensure_indices()
        report["indexed"] = ingest_breaking_changes(store, settings)
    return report


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="sync_breaking_changes", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--url", help="upgrading guide URL (default: BC_SOURCE_URL)")
    src.add_argument("--file", help="use a local HTML file instead of downloading")
    ap.add_argument("--data-dir", help="override DATA_DIR")
    ap.add_argument("--no-llm", action="store_true", help="do not call the LLM")
    ap.add_argument("--force-llm", action="store_true", help="ignore the per-entry cache")
    ap.add_argument("--min-version", help="only send entries >= this version to the LLM (default BC_MIN_VERSION)")
    ap.add_argument("--categories", help="comma separated categories sent to the LLM (default BC_LLM_CATEGORIES)")
    ap.add_argument("--max-entries", type=int, help="max LLM calls in this run (cost guard)")
    ap.add_argument("--no-index", action="store_true", help="write files only, do not index into Elasticsearch")
    ap.add_argument("--dry-run", action="store_true", help="fetch + parse + diff only, write nothing")
    report = run(ap.parse_args(argv))
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False, default=str)
    print()


if __name__ == "__main__":
    main()
