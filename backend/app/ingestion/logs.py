"""Pipeline C — Log ingestion (deterministic, no AI).

Parses Keycloak JSON (ECS) console/file logs: HTTP access log records
(logger `http-access-log`), event records (logger `org.keycloak.events`) and
generic application records. Applies the attribution rule

    client_id = extracted_client_id or "anonymous"

and stores `client_identified: false` when no Keycloak client can be attributed
(which does NOT mean the caller was unauthenticated).

Two clearly separated origins are supported:
  * `synthetic-fixture`  — data/logs/*.jsonl, predefined scenarios
  * `keycloak-runtime`   — logs actually produced by the Keycloak containers
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from ..store import LOGS, Store
from ..utils import get_path, stable_id

ANONYMOUS = "anonymous"
ORIGIN_FIXTURE = "synthetic-fixture"
ORIGIN_RUNTIME = "keycloak-runtime"

ACCESS_LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+)(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<bytes>\S+)(?: "(?P<referer>[^"]*)" "(?P<ua>[^"]*)")?'
)
EVENT_PAIR = re.compile(r'(\w+)=(?:"([^"]*)"|([^,\s]*))')
REALM_PATH = re.compile(r"^/realms/([^/]+)")
MDC_CLIENT_KEYS = ("kc.clientId", "clientId", "kc_clientId")


def _mdc_client(rec: dict) -> str | None:
    mdc = rec.get("mdc") if isinstance(rec.get("mdc"), dict) else {}
    for key in MDC_CLIENT_KEYS:
        for v in (mdc.get(key), rec.get(f"mdc.{key}"), rec.get(key)):
            if v and v != "null":
                return str(v)
    return None


def _clean(v: str | None) -> str | None:
    return None if v in (None, "", "null", "-") else v


def parse_record(rec: dict, origin: str, source_file: str, instance: str | None = None,
                 version: str | None = None) -> dict | None:
    logger = get_path(rec, "log.logger") or rec.get("loggerName") or ""
    message = rec.get("message") or ""
    doc: dict = {
        "@timestamp": rec.get("@timestamp") or rec.get("timestamp"),
        "message": message,
        "log": {"level": get_path(rec, "log.level") or rec.get("level"), "logger": logger},
        "labels": {"origin": origin, "source_file": source_file},
        "keycloak": {"instance": instance, "version": version or get_path(rec, "service.version")},
        "url": {}, "http": {}, "event": {},
    }
    client_id, source = _mdc_client(rec), "mdc"
    m = ACCESS_LINE.match(message)  # logger is "http-access-log" in Keycloak, but match on content
    if m:
        target = m["target"]
        split = urlsplit(target)
        query = split.query
        params = parse_qs(query, keep_blank_values=True)
        doc["event"] = {"kind": "access", "dataset": "keycloak.access",
                        "outcome": "success" if int(m["status"]) < 400 else "failure"}
        doc["http"] = {"request": {"method": m["method"]},
                       "response": {"status_code": int(m["status"]),
                                    "bytes": int(m["bytes"]) if m["bytes"].isdigit() else 0}}
        doc["url"] = {"original": target, "path": unquote(split.path), "query": query,
                      "query_param_names": sorted(params)}
        doc["source"] = {"ip": m["ip"]} if re.match(r"^[\d.:a-fA-F]+$", m["ip"]) else {}
        doc["user_agent"] = {"original": m["ua"]} if m["ua"] else {}
        if not client_id and params.get("client_id"):
            client_id, source = params["client_id"][0], "query"
        rm = REALM_PATH.match(split.path)
        doc["keycloak"]["realm"] = rm.group(1) if rm else None
    elif logger == "org.keycloak.events" or message.startswith("type="):
        pairs = {k: _clean(a if a != "" else b) for k, a, b in EVENT_PAIR.findall(message)}
        doc["event"] = {"kind": "keycloak-event", "dataset": "keycloak.event", "action": pairs.get("type"),
                        "outcome": "failure" if pairs.get("error") else "success"}
        doc["keycloak"].update(realm=pairs.get("realmName"), user_id=pairs.get("userId"), error=pairs.get("error"))
        if pairs.get("ipAddress"):
            doc["source"] = {"ip": pairs["ipAddress"]}
        if not client_id and pairs.get("clientId"):
            client_id, source = pairs["clientId"], "event"
    else:
        doc["event"] = {"kind": "application", "dataset": "keycloak.log"}
        doc["keycloak"]["realm"] = get_path(rec, "mdc.kc.realmName") or (rec.get("mdc") or {}).get("kc.realmName")

    # ---- attribution rule ----
    doc["client_id"] = client_id or ANONYMOUS
    doc["client_identified"] = client_id is not None
    doc["client_id_source"] = source if client_id else "none"
    doc["client"] = {"id": doc["client_id"]}
    raw = json.dumps(rec, sort_keys=True)
    doc["log_id"] = stable_id(origin, source_file, raw, length=32)
    return doc


def iter_jsonl(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue  # non-JSON lines (e.g. banner) are ignored
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def ingest_files(store: Store, files: list[Path], origin: str, instance: str | None = None,
                 version: str | None = None) -> dict:
    docs, per_file = [], {}
    for f in files:
        n = 0
        for rec in iter_jsonl(f):
            d = parse_record(rec, origin, f.name, instance, version)
            if d:
                docs.append((d["log_id"], d))
                n += 1
        per_file[str(f.name)] = n
    store.upsert_many(LOGS, docs)
    anonymous = sum(1 for _, d in docs if not d["client_identified"])
    return {"origin": origin, "records": len(docs), "anonymous": anonymous, "files": per_file}


def ingest_fixture_logs(store: Store, settings) -> dict:
    files = sorted((settings.data_dir / "logs").glob("*.jsonl"))
    return ingest_files(store, files, ORIGIN_FIXTURE)


def ingest_runtime_logs(store: Store, settings) -> dict:
    """Ingest logs written by the Keycloak containers: <KEYCLOAK_LOG_DIR>/<instance>/*.log."""
    results = {}
    base = settings.keycloak_log_dir
    if not base.exists():
        return {"origin": ORIGIN_RUNTIME, "records": 0, "instances": {}, "note": f"{base} not found"}
    for inst_dir in sorted(p for p in base.iterdir() if p.is_dir()):
        files = sorted(list(inst_dir.glob("*.log")) + list(inst_dir.glob("*.jsonl")))
        version = settings.instance_versions.get(inst_dir.name)
        results[inst_dir.name] = ingest_files(store, files, ORIGIN_RUNTIME, inst_dir.name, version)
    return {"origin": ORIGIN_RUNTIME, "records": sum(r["records"] for r in results.values()), "instances": results}
