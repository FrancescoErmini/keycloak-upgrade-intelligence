"""Command line entry point:  python -m app.cli {bootstrap|ingest|assess} ..."""
from __future__ import annotations

import argparse
import json

from .config import get_settings
from .detection.analyzers import run_assessment
from .services import bootstrap, ingest_all
from .store import build_store


def main() -> None:
    ap = argparse.ArgumentParser(prog="kc-upgrade-analyzer")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("bootstrap", help="ingest all sources and run the scenario assessments")
    ing = sub.add_parser("ingest", help="run pipelines A, B and C")
    ing.add_argument("--no-runtime", action="store_true")
    a = sub.add_parser("assess", help="run one assessment")
    a.add_argument("source_version")
    a.add_argument("target_version")
    a.add_argument("--origin", action="append", help="restrict runtime evidence to a log origin")
    a.add_argument("--label")
    args = ap.parse_args()

    settings = get_settings()
    store = build_store(settings)
    store.ensure_indices()
    if args.cmd == "bootstrap":
        out = bootstrap(store, settings)
    elif args.cmd == "ingest":
        out = ingest_all(store, settings, include_runtime=not args.no_runtime)
    else:
        out = run_assessment(store, args.source_version, args.target_version, log_origins=args.origin, label=args.label)
    print(json.dumps(out, indent=2, default=str))


if __name__ == "__main__":
    main()
