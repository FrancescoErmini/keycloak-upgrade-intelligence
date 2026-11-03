"""Pipeline B — Realm ingestion (deterministic, no AI).

Reads a Keycloak realm export plus the optional client inventory, normalizes every
client (grant types, redirect URIs, protocol mappers, ...) and indexes one document
per client in kc-realm-snapshots, plus one `snapshot` summary document.
"""
from __future__ import annotations

import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from ..store import REALMS, Store
from ..utils import stable_id

_URI = re.compile(r"^(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)(?P<rest>.*)$")


def analyze_redirect_uri(uri: str, root_url: str | None = None) -> dict:
    if uri in ("*", "+", "-"):
        return {"uri": uri, "scheme": None, "authority": None, "host_wildcard": uri == "*",
                "path_wildcard": uri == "*", "kind": "special"}
    resolved = uri
    if uri.startswith("/") and root_url:
        resolved = root_url.rstrip("/") + uri
    m = _URI.match(resolved)
    if not m:
        return {"uri": uri, "scheme": None, "authority": None, "host_wildcard": False,
                "path_wildcard": uri.endswith("*"), "kind": "relative" if uri.startswith("/") else "custom"}
    return {
        "uri": uri,
        "scheme": m["scheme"].lower(),
        "authority": m["authority"],
        "host_wildcard": "*" in m["authority"],
        "path_wildcard": "*" in m["rest"],
        "kind": "absolute",
    }


def classify_client(c: dict) -> str:
    if c.get("protocol") == "saml":
        return "saml"
    if c.get("bearerOnly") or c.get("implicitFlowEnabled") or (
        c.get("directAccessGrantsEnabled") and not c.get("standardFlowEnabled")
    ):
        return "legacy"
    if c.get("publicClient"):
        return "public_spa"
    if c.get("serviceAccountsEnabled") and not c.get("standardFlowEnabled"):
        return "client_credentials"
    if c.get("standardFlowEnabled", True):
        return "authorization_code"
    return "other"


def grant_types(c: dict) -> list[str]:
    if c.get("protocol") == "saml":
        return ["saml"]
    g = []
    if c.get("standardFlowEnabled", True) and not c.get("bearerOnly"):
        g.append("authorization_code")
    if c.get("implicitFlowEnabled"):
        g.append("implicit")
    if c.get("directAccessGrantsEnabled"):
        g.append("password")
    if c.get("serviceAccountsEnabled"):
        g.append("client_credentials")
    if c.get("bearerOnly"):
        g.append("bearer-only")
    return g


def _bool(v) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() == "true"
    return None


def normalize_mapper(m: dict) -> dict:
    cfg = m.get("config") or {}
    return {
        "name": m.get("name"),
        "type": m.get("protocolMapper"),
        "protocol": m.get("protocol"),
        "claim_name": cfg.get("claim.name"),
        "multivalued": _bool(cfg.get("multivalued")),
    }


def normalize_client(c: dict, realm: str, snapshot_id: str, inventory: dict | None, now: str) -> dict:
    attrs = {k: str(v) for k, v in (c.get("attributes") or {}).items()}
    root = c.get("rootUrl")
    redirects = list(c.get("redirectUris") or [])
    plru = [u for u in attrs.get("post.logout.redirect.uris", "").split("##") if u]
    return {
        "doc_type": "client",
        "snapshot_id": snapshot_id,
        "realm": realm,
        "client_id": c["clientId"],
        "name": c.get("name") or c["clientId"],
        "protocol": c.get("protocol", "openid-connect"),
        "client_type": classify_client(c),
        "enabled": c.get("enabled", True),
        "public_client": bool(c.get("publicClient", False)),
        "bearer_only": bool(c.get("bearerOnly", False)),
        "grant_types": grant_types(c),
        "root_url": root,
        "redirect_uris": redirects,
        "post_logout_redirect_uris": plru,
        "redirect_uri_analysis": [analyze_redirect_uri(u, root) for u in redirects],
        "web_origins": list(c.get("webOrigins") or []),
        "protocol_mappers": [normalize_mapper(m) for m in c.get("protocolMappers") or []],
        "attributes": attrs,
        "inventory": inventory or {},
        "ingested_at": now,
    }


# Keycloak-created clients present in every realm export; not part of the assessed inventory.
BUILTIN_CLIENTS = {"account", "account-console", "admin-cli", "broker", "realm-management", "security-admin-console"}


def ingest_realm(store: Store, settings, realm_file: Path | None = None, inventory_file: Path | None = None) -> dict:
    realm_file = realm_file or settings.data_dir / "realms" / "enterprise-realm.json"
    inventory_file = inventory_file or settings.data_dir / "realms" / "client-inventory.json"
    realm_json = json.loads(realm_file.read_text(encoding="utf-8"))
    inventory = {}
    if inventory_file and inventory_file.exists():
        inventory = {c["client_id"]: c for c in json.loads(inventory_file.read_text(encoding="utf-8"))["clients"]}

    realm = realm_json["realm"]
    clients = [c for c in realm_json.get("clients", []) if c["clientId"] not in BUILTIN_CLIENTS]
    # snapshot id = content hash of the client configuration: same export -> same snapshot
    snapshot_id = f"{realm}-{stable_id(sorted(clients, key=lambda c: c['clientId']), length=12)}"
    ts = datetime.now(timezone.utc).isoformat()
    docs = [normalize_client(c, realm, snapshot_id, inventory.get(c["clientId"]), ts) for c in clients]
    types = Counter(d["client_type"] for d in docs)
    summary = {
        "doc_type": "snapshot",
        "snapshot_id": snapshot_id,
        "realm": realm,
        "source_file": realm_file.name,
        "client_count": len(docs),
        "client_types": dict(types),
        "ingested_at": ts,
    }
    store.upsert_many(REALMS, [(f"{snapshot_id}:{d['client_id']}", d) for d in docs] + [(f"snapshot:{snapshot_id}", summary)])
    return {"snapshot_id": snapshot_id, "realm": realm, "clients": len(docs), "client_types": dict(types)}


def latest_snapshot(store: Store) -> dict | None:
    snaps = store.find(REALMS, {"doc_type": "snapshot"})
    return max(snaps, key=lambda s: s["ingested_at"]) if snaps else None
