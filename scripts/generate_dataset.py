#!/usr/bin/env python3
"""Deterministic generator for the POC demo dataset.

Produces, under data/:
  realms/enterprise-realm.json      Keycloak realm export with 100 fictitious clients
  realms/client-inventory.json      CMDB-like ownership / criticality metadata
  logs/access-logs.jsonl            ECS JSON records of the Keycloak HTTP access log (synthetic fixtures)
  logs/keycloak-events.jsonl        ECS JSON records of org.keycloak.events (synthetic fixtures)
  scenarios/expected-findings.json  Ground truth used by the accuracy tests

The ground truth is derived from what the generator *plants* in the data, never
from the detection engine, so the tests are a genuine check of the engine.

Usage:  python scripts/generate_dataset.py [--data-dir data]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from packaging.version import Version

REALM = "demo"
SEED = 42
BASE_TS = datetime(2026, 10, 1, 7, 0, 0, tzinfo=timezone.utc)

ROLE_MAPPER_TYPES = ("oidc-usermodel-realm-role-mapper", "oidc-usermodel-client-role-mapper")


# --------------------------------------------------------------------------------------
# Client specification
# --------------------------------------------------------------------------------------
@dataclass
class Spec:
    client_id: str
    kind: str  # authorization_code | client_credentials | public_spa | saml | legacy
    app: str
    host: str
    team: str
    criticality: str = "medium"
    enabled: bool = True
    redirect_uris: list[str] | None = None
    mappers: list[dict] = field(default_factory=list)
    legacy_flavour: str = "implicit"  # implicit | bearer_only | direct_grant
    active: bool = True
    # planted behaviour
    plant: dict[str, dict] = field(default_factory=dict)  # bc_id -> {"confidence":..., "attribution":...}
    logout_style: str | None = None  # legacy-explicit | legacy-inferred | modern
    non_normalized: str | None = None  # double-slash | dot-segment | mdc-token


def role_mapper(kind: str, multivalued: bool, claim: str = "roles") -> dict:
    mapper_type = "oidc-usermodel-realm-role-mapper" if kind == "realm" else "oidc-usermodel-client-role-mapper"
    cfg = {
        "multivalued": str(multivalued).lower(),
        "claim.name": claim,
        "jsonType.label": "String",
        "id.token.claim": "true",
        "access.token.claim": "true",
        "userinfo.token.claim": "true",
        "introspection.token.claim": "true",
    }
    if kind == "client":
        cfg["usermodel.clientRoleMapping.clientId"] = "${client_id}"
    return {
        "name": f"{kind} roles ({'multi' if multivalued else 'single'})",
        "protocol": "openid-connect",
        "protocolMapper": mapper_type,
        "consentRequired": False,
        "config": cfg,
    }


def attribute_mapper(attr: str) -> dict:
    return {
        "name": f"{attr} attribute",
        "protocol": "openid-connect",
        "protocolMapper": "oidc-usermodel-attribute-mapper",
        "consentRequired": False,
        "config": {
            "user.attribute": attr,
            "claim.name": attr,
            "jsonType.label": "String",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true",
        },
    }


AUTH_CODE_APPS = [
    "hr-portal", "crm-web", "intranet", "expense-web", "procurement-web", "wiki-web", "old-claims-web",
    "travel-web", "payroll-web", "helpdesk-web", "billing-web", "analytics-web", "timesheet-web",
    "learning-web", "recruiting-web", "assets-web", "contracts-web", "legal-web", "facilities-web",
    "benefits-web", "marketing-web", "partner-web", "supplier-web", "quality-web", "projects-web",
    "compliance-web", "audit-web", "treasury-web", "risk-web", "sales-web", "support-web",
    "events-web", "fleet-web", "safety-web", "docs-web",
]
CLIENT_CREDS_APPS = [
    "svc-reporting", "svc-ledger-sync", "svc-inventory-sync", "svc-billing-batch", "svc-notifications",
    "svc-search-indexer", "svc-payments", "svc-orders", "svc-shipping", "svc-pricing", "svc-catalog",
    "svc-identity-sync", "svc-audit-export", "svc-crm-sync", "svc-hr-sync", "svc-mailer", "svc-scheduler",
    "svc-archiver", "svc-metrics", "svc-fraud", "svc-loyalty", "svc-tax", "svc-gateway", "svc-etl",
    "svc-backup",
]
SPA_APPS = [
    "spa-catalog", "spa-checkout", "spa-dashboard", "spa-mobile-web", "spa-store-locator", "spa-chat",
    "spa-kiosk", "spa-survey", "spa-booking", "spa-wallet", "spa-feedback", "spa-careers",
    "spa-status", "spa-forum", "spa-maps",
]
SAML_APPS = [
    "saml-payroll", "saml-erp", "saml-expenses", "saml-lms", "saml-wiki", "saml-vpn-portal",
    "saml-ticketing", "saml-crm", "saml-docs", "saml-intranet", "saml-benefits", "saml-procurement",
    "saml-signing", "saml-travel", "saml-archive",
]
LEGACY_APPS = [
    ("legacy-portal", "implicit"), ("legacy-claims", "implicit"), ("legacy-reports", "implicit"),
    ("legacy-api-orders", "bearer_only"), ("legacy-api-stock", "bearer_only"), ("legacy-api-hr", "bearer_only"),
    ("legacy-kiosk", "direct_grant"), ("legacy-cli", "direct_grant"), ("legacy-intranet", "implicit"),
    ("legacy-batch-ui", "direct_grant"),
]
TEAMS = ["Team Atlas", "Team Borealis", "Team Cobalt", "Team Delta", "Team Ember", "Team Fjord", "Team Granite"]
CRITICALITY = ["critical", "high", "medium", "medium", "low"]


def host_of(app: str) -> str:
    if app.startswith("saml-"):
        return f"sp-{app[5:]}.example.com"
    if app.startswith("spa-"):
        return f"{app[4:]}-app.example.com"
    return f"{app.replace('-web', '').replace('svc-', 'api-')}.example.com"


def build_specs() -> list[Spec]:
    rnd = random.Random(SEED)
    specs: list[Spec] = []

    def mk(cid: str, kind: str, **kw) -> Spec:
        s = Spec(
            client_id=cid,
            kind=kind,
            app=cid.replace("-", " ").title(),
            host=host_of(cid),
            team=TEAMS[len(specs) % len(TEAMS)],
            criticality=CRITICALITY[rnd.randrange(len(CRITICALITY))],
            **kw,
        )
        specs.append(s)
        return s

    # ---- OIDC Authorization Code (35) --------------------------------------------------
    for app in AUTH_CODE_APPS:
        s = mk(app, "authorization_code")
        s.redirect_uris = [f"https://{s.host}/*"]
    by_id = {s.client_id: s for s in specs}

    # KC-BC-001 positives (wildcard in host name)
    for cid in ("hr-portal", "crm-web", "intranet", "expense-web"):
        by_id[cid].redirect_uris = [f"https://{by_id[cid].host}*"]
        by_id[cid].plant["KC-BC-001"] = {"confidence": "high"}
    for cid in ("procurement-web", "wiki-web"):
        by_id[cid].redirect_uris = [f"https://{by_id[cid].host}*", f"https://{by_id[cid].host}/callback"]
        by_id[cid].active = False
        by_id[cid].plant["KC-BC-001"] = {"confidence": "medium"}
    s = by_id["old-claims-web"]
    s.redirect_uris = [f"https://{s.host}*"]
    s.enabled = False
    s.active = False
    s.plant["KC-BC-001"] = {"confidence": "low", "note": "client disabled: ambiguous"}

    # KC-BC-002 positives (legacy logout)
    for cid in ("travel-web", "payroll-web", "helpdesk-web"):
        by_id[cid].logout_style = "legacy-explicit"
        by_id[cid].plant["KC-BC-002"] = {"confidence": "high", "attribution": "explicit"}
    by_id["billing-web"].logout_style = "legacy-inferred"
    by_id["billing-web"].plant["KC-BC-002"] = {"confidence": "medium", "attribution": "inferred-redirect-uri"}
    # Compatible lookalikes: modern RP-initiated logout
    for cid in ("timesheet-web", "learning-web", "recruiting-web", "assets-web"):
        by_id[cid].logout_style = "modern"

    # KC-BC-004 positive + compatible lookalikes
    by_id["analytics-web"].mappers = [role_mapper("realm", multivalued=False), attribute_mapper("department")]
    by_id["analytics-web"].plant["KC-BC-004"] = {"confidence": "high"}
    by_id["contracts-web"].mappers = [role_mapper("realm", multivalued=True)]
    by_id["legal-web"].mappers = [role_mapper("client", multivalued=True), attribute_mapper("employee_id")]
    # A few inactive, compatible clients
    for cid in ("events-web", "fleet-web", "safety-web"):
        by_id[cid].active = False

    # ---- OIDC Client Credentials (25) ---------------------------------------------------
    for app in CLIENT_CREDS_APPS:
        mk(app, "client_credentials")
    by_id = {s.client_id: s for s in specs}
    by_id["svc-reporting"].mappers = [role_mapper("realm", multivalued=False)]
    by_id["svc-reporting"].plant["KC-BC-004"] = {"confidence": "high"}
    by_id["svc-ledger-sync"].mappers = [role_mapper("client", multivalued=False, claim="ledger_roles")]
    by_id["svc-ledger-sync"].active = False
    by_id["svc-ledger-sync"].plant["KC-BC-004"] = {"confidence": "medium"}
    by_id["svc-inventory-sync"].non_normalized = "mdc-token"
    by_id["svc-inventory-sync"].plant["KC-BC-003"] = {"confidence": "high", "attribution": "explicit"}
    by_id["svc-payments"].mappers = [role_mapper("realm", multivalued=True)]
    by_id["svc-archiver"].active = False

    # ---- OIDC Public / SPA (15) ---------------------------------------------------------
    for app in SPA_APPS:
        s = mk(app, "public_spa")
        s.redirect_uris = [f"https://{s.host}/*"]
    by_id = {s.client_id: s for s in specs}
    by_id["spa-catalog"].non_normalized = "double-slash"
    by_id["spa-catalog"].plant["KC-BC-003"] = {"confidence": "high", "attribution": "explicit"}
    by_id["spa-checkout"].non_normalized = "dot-segment"
    by_id["spa-checkout"].plant["KC-BC-003"] = {"confidence": "high", "attribution": "explicit"}
    by_id["spa-status"].active = False

    # ---- SAML (15) ----------------------------------------------------------------------
    for app in SAML_APPS:
        s = mk(app, "saml")
        s.redirect_uris = [f"https://{s.host}/saml/acs/*"]

    # ---- Legacy and special configurations (10) ------------------------------------------
    for app, flavour in LEGACY_APPS:
        s = mk(app, "legacy", legacy_flavour=flavour)
        if flavour == "implicit":
            s.redirect_uris = [f"https://{s.host}/*"]
        elif flavour == "direct_grant":
            s.redirect_uris = []
        else:
            s.redirect_uris = []
    by_id = {s.client_id: s for s in specs}
    by_id["legacy-portal"].host = "example.com"
    by_id["legacy-portal"].redirect_uris = ["https://example.com*"]
    by_id["legacy-portal"].plant["KC-BC-001"] = {"confidence": "high"}
    by_id["legacy-portal"].logout_style = "legacy-inferred"
    by_id["legacy-portal"].plant["KC-BC-002"] = {"confidence": "medium", "attribution": "inferred-redirect-uri"}
    by_id["legacy-portal"].criticality = "critical"
    by_id["legacy-claims"].redirect_uris = [f"https://{by_id['legacy-claims'].host}*"]
    by_id["legacy-claims"].plant["KC-BC-001"] = {"confidence": "high"}
    by_id["legacy-reports"].redirect_uris = [f"https://{by_id['legacy-reports'].host}*"]
    by_id["legacy-reports"].active = False
    by_id["legacy-reports"].plant["KC-BC-001"] = {"confidence": "medium"}

    assert len(specs) == 100, len(specs)
    return specs


# --------------------------------------------------------------------------------------
# Realm export
# --------------------------------------------------------------------------------------
def secret_for(cid: str) -> str:
    return hashlib.sha256(f"poc-secret:{cid}".encode()).hexdigest()[:32]


def client_rep(s: Spec) -> dict:
    if s.kind == "saml":
        return {
            "clientId": s.client_id,
            "name": s.app,
            "description": f"SAML service provider for {s.app} (fictitious)",
            "enabled": s.enabled,
            "protocol": "saml",
            "rootUrl": f"https://{s.host}",
            "redirectUris": s.redirect_uris or [],
            "frontchannelLogout": True,
            "fullScopeAllowed": True,
            "attributes": {
                "saml.signature.algorithm": "RSA_SHA256",
                "saml_name_id_format": "username",
                "saml.client.signature": "false",
                "saml.force.post.binding": "true",
                "saml.server.signature": "true",
                "saml_assertion_consumer_url_post": f"https://{s.host}/saml/acs",
            },
            "protocolMappers": [],
        }

    rep: dict = {
        "clientId": s.client_id,
        "name": s.app,
        "description": f"{s.app} (fictitious, generated for the POC)",
        "enabled": s.enabled,
        "protocol": "openid-connect",
        "publicClient": False,
        "bearerOnly": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "clientAuthenticatorType": "client-secret",
        "fullScopeAllowed": True,
        "redirectUris": s.redirect_uris or [],
        "webOrigins": [],
        "attributes": {},
        "protocolMappers": s.mappers,
    }
    if s.kind == "authorization_code":
        rep.update(standardFlowEnabled=True, secret=secret_for(s.client_id), rootUrl=f"https://{s.host}", webOrigins=["+"])
        rep["attributes"]["post.logout.redirect.uris"] = f"https://{s.host}/*"
    elif s.kind == "client_credentials":
        rep.update(serviceAccountsEnabled=True, secret=secret_for(s.client_id))
    elif s.kind == "public_spa":
        rep.update(publicClient=True, standardFlowEnabled=True, webOrigins=[f"https://{s.host}"])
        rep["attributes"]["pkce.code.challenge.method"] = "S256"
        rep["attributes"]["post.logout.redirect.uris"] = f"https://{s.host}/*"
    elif s.kind == "legacy":
        if s.legacy_flavour == "implicit":
            rep.update(standardFlowEnabled=True, implicitFlowEnabled=True, secret=secret_for(s.client_id), rootUrl=f"https://{s.host}")
        elif s.legacy_flavour == "bearer_only":
            rep.update(bearerOnly=True, secret=secret_for(s.client_id))
        else:
            rep.update(publicClient=True, directAccessGrantsEnabled=True)
    return rep


def build_realm(specs: list[Spec]) -> dict:
    users = [
        {
            "username": "alice",
            "enabled": True,
            "email": "alice@example.com",
            "emailVerified": True,
            "firstName": "Alice",
            "lastName": "Example",
            "credentials": [{"type": "password", "value": "alice-password", "temporary": False}],
            "realmRoles": ["user", "reporting-reader"],
        }
    ]
    for s in specs:
        if s.kind == "client_credentials":
            users.append({
                "username": f"service-account-{s.client_id}",
                "enabled": True,
                "serviceAccountClientId": s.client_id,
                "realmRoles": ["reporting-reader"] if s.client_id == "svc-reporting" else ["user"],
            })
    return {
        "realm": REALM,
        "displayName": "Demo enterprise realm (fictitious)",
        "enabled": True,
        "sslRequired": "none",
        "registrationAllowed": False,
        "eventsEnabled": True,
        "eventsListeners": ["jboss-logging"],
        "adminEventsEnabled": False,
        "roles": {
            "realm": [
                {"name": "user", "description": "Standard user"},
                {"name": "admin", "description": "Administrator"},
                {"name": "reporting-reader", "description": "Can read reports"},
                {"name": "auditor", "description": "Read-only auditor"},
            ]
        },
        "users": users,
        "clients": [client_rep(s) for s in specs],
    }


def build_inventory(specs: list[Spec]) -> dict:
    stacks = {
        "authorization_code": "Java / Spring Boot",
        "client_credentials": "Go / batch service",
        "public_spa": "TypeScript / React",
        "saml": "COTS SAML SP",
        "legacy": "Legacy (JSP / .NET Framework)",
    }
    return {
        "realm": REALM,
        "generated_by": "scripts/generate_dataset.py",
        "notice": "All applications, teams and contacts are fictitious.",
        "clients": [
            {
                "client_id": s.client_id,
                "application": s.app,
                "owner_team": s.team,
                "business_criticality": s.criticality,
                "environment": "production",
                "technical_contact": f"{s.team.lower().replace(' ', '-')}@example.com",
                "tech_stack": stacks[s.kind],
            }
            for s in specs
        ],
    }


# --------------------------------------------------------------------------------------
# Logs
# --------------------------------------------------------------------------------------
class Clock:
    def __init__(self, rnd: random.Random):
        self.t = BASE_TS
        self.rnd = rnd

    def tick(self) -> datetime:
        self.t += timedelta(seconds=self.rnd.randint(1, 40), milliseconds=self.rnd.randint(0, 999))
        return self.t


def clf_time(t: datetime) -> str:
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def iso(t: datetime) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def access_record(t: datetime, ip: str, method: str, target: str, status: int, size: int,
                  ua: str, mdc: dict | None = None) -> dict:
    line = f'{ip} - - [{clf_time(t)}] "{method} {target} HTTP/1.1" {status} {size} "-" "{ua}"'
    rec = {
        "@timestamp": iso(t),
        "log.level": "INFO",
        "message": line,
        "ecs.version": "1.12.2",
        "log.logger": "http-access-log",
        "process.thread.name": "executor-thread-1",
        "service.name": "keycloak",
        "host.hostname": "kc-prod-fixture",
        "labels.origin": "synthetic-fixture",
    }
    if mdc:
        rec["mdc"] = mdc
    return rec


def event_record(t: datetime, etype: str, client_id: str | None, ip: str, user: str | None,
                 error: str | None = None) -> dict:
    parts = [f'type="{etype}"', 'realmId="0f6d1c38-demo"', f'realmName="{REALM}"',
             f'clientId="{client_id}"' if client_id else 'clientId="null"',
             f'userId="{user}"' if user else 'userId="null"',
             f'ipAddress="{ip}"']
    if error:
        parts.append(f'error="{error}"')
    return {
        "@timestamp": iso(t),
        "log.level": "WARN" if error else "DEBUG",
        "message": ", ".join(parts),
        "ecs.version": "1.12.2",
        "log.logger": "org.keycloak.events",
        "process.thread.name": "executor-thread-2",
        "service.name": "keycloak",
        "host.hostname": "kc-prod-fixture",
        "labels.origin": "synthetic-fixture",
    }


UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Firefox/131.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) Safari/605.1.15",
    "okhttp/4.12.0",
    "Go-http-client/2.0",
    "python-requests/2.32.3",
]


def auth_target(client_id: str, redirect: str, prefix: str = f"/realms/{REALM}/protocol/openid-connect/auth") -> str:
    q = urlencode({"client_id": client_id, "response_type": "code", "scope": "openid",
                   "redirect_uri": redirect, "state": "st", "nonce": "n"})
    return f"{prefix}?{q}"


def build_logs(specs: list[Spec]) -> tuple[list[dict], list[dict]]:
    rnd = random.Random(SEED + 1)
    clock = Clock(rnd)
    access: list[dict] = []
    events: list[dict] = []

    def ip() -> str:
        return f"10.20.{rnd.randint(0, 30)}.{rnd.randint(2, 250)}"

    users = [f"user-{i:04d}" for i in range(1, 60)]
    token_path = f"/realms/{REALM}/protocol/openid-connect/token"

    for s in specs:
        if s.active:
            for _ in range(rnd.randint(4, 9)):
                t, a, u = clock.tick(), ip(), rnd.choice(users)
                if s.kind in ("authorization_code", "public_spa") or (s.kind == "legacy" and s.legacy_flavour == "implicit"):
                    redirect = f"https://{s.host}/callback"
                    access.append(access_record(t, a, "GET", auth_target(s.client_id, redirect), 200, 4211, UAS[rnd.randint(0, 1)]))
                    events.append(event_record(clock.tick(), "LOGIN", s.client_id, a, u))
                    # Token exchange: client id is only in the POST body -> anonymous in the access log
                    mdc = {"kc.clientId": s.client_id, "kc.realmName": REALM} if rnd.random() < 0.4 else None
                    access.append(access_record(clock.tick(), a, "POST", token_path, 200, 2650, "okhttp/4.12.0", mdc=mdc))
                    events.append(event_record(clock.tick(), "CODE_TO_TOKEN", s.client_id, a, u))
                elif s.kind == "client_credentials":
                    mdc = {"kc.clientId": s.client_id, "kc.realmName": REALM} if rnd.random() < 0.4 else None
                    access.append(access_record(t, a, "POST", token_path, 200, 1830, "Go-http-client/2.0", mdc=mdc))
                    events.append(event_record(clock.tick(), "CLIENT_LOGIN", s.client_id, a, f"sa-{s.client_id}"))
                elif s.kind == "saml":
                    access.append(access_record(t, a, "POST", f"/realms/{REALM}/protocol/saml", 200, 9120, UAS[0]))
                    events.append(event_record(clock.tick(), "LOGIN", s.client_id, a, u))
                elif s.legacy_flavour == "bearer_only":
                    access.append(access_record(t, a, "POST", f"{token_path}/introspect", 200, 640, "python-requests/2.32.3"))
                    events.append(event_record(clock.tick(), "INTROSPECT_TOKEN", s.client_id, a, None))
                else:  # direct grant
                    access.append(access_record(t, a, "POST", token_path, 200, 2650, "python-requests/2.32.3"))
                    events.append(event_record(clock.tick(), "LOGIN", s.client_id, a, u))

        # ---- planted logout behaviour -----------------------------------------------
        logout_path = f"/realms/{REALM}/protocol/openid-connect/logout"
        if s.logout_style == "legacy-explicit":
            for _ in range(3):
                q = urlencode({"client_id": s.client_id, "redirect_uri": f"https://{s.host}/"})
                access.append(access_record(clock.tick(), ip(), "GET", f"{logout_path}?{q}", 302, 0, UAS[0]))
        elif s.logout_style == "legacy-inferred":
            for _ in range(3):
                q = urlencode({"redirect_uri": f"https://{s.host}/logged-out"})
                access.append(access_record(clock.tick(), ip(), "GET", f"{logout_path}?{q}", 302, 0, UAS[1]))
        elif s.logout_style == "modern":
            for _ in range(3):
                q = urlencode({"client_id": s.client_id, "post_logout_redirect_uri": f"https://{s.host}/",
                               "id_token_hint": "eyJhbGciOiJSUzI1NiJ9.fixture.sig"})
                access.append(access_record(clock.tick(), ip(), "GET", f"{logout_path}?{q}", 302, 0, UAS[0]))

        # ---- planted non-normalized paths -----------------------------------------
        if s.non_normalized == "double-slash":
            for _ in range(3):
                target = auth_target(s.client_id, f"https://{s.host}/callback", f"/realms/{REALM}//protocol/openid-connect/auth")
                access.append(access_record(clock.tick(), ip(), "GET", target, 200, 4211, UAS[1]))
        elif s.non_normalized == "dot-segment":
            for _ in range(3):
                target = auth_target(s.client_id, f"https://{s.host}/callback",
                                     f"/realms/{REALM}/protocol/openid-connect/../openid-connect/auth")
                access.append(access_record(clock.tick(), ip(), "GET", target, 200, 4211, UAS[0]))
        elif s.non_normalized == "mdc-token":
            for _ in range(3):
                access.append(access_record(clock.tick(), ip(), "POST", f"/realms/{REALM}/protocol//openid-connect/token",
                                            200, 1830, "Go-http-client/2.0",
                                            mdc={"kc.clientId": s.client_id, "kc.realmName": REALM}))

    # ---- anonymous planted traffic -------------------------------------------------------
    for _ in range(2):  # legacy logout from an unknown application: cannot be attributed
        q = urlencode({"redirect_uri": "https://unknown-app.example.org/"})
        access.append(access_record(clock.tick(), ip(), "GET", f"/realms/{REALM}/protocol/openid-connect/logout?{q}", 302, 0, UAS[0]))
    for _ in range(4):  # non-normalized discovery call without any client information
        access.append(access_record(clock.tick(), ip(), "GET", f"/realms/{REALM}/./.well-known/openid-configuration", 200, 6120, "curl/8.9.1"))
    for _ in range(12):  # regular discovery / certs calls without client information
        path = rnd.choice([f"/realms/{REALM}/.well-known/openid-configuration", f"/realms/{REALM}/protocol/openid-connect/certs"])
        access.append(access_record(clock.tick(), ip(), "GET", path, 200, 3100, rnd.choice(UAS)))
    # failed client authentication without a client id
    for _ in range(3):
        t, a = clock.tick(), ip()
        access.append(access_record(t, a, "POST", token_path, 401, 89, "curl/8.9.1"))
        events.append(event_record(clock.tick(), "CLIENT_LOGIN_ERROR", None, a, None, error="invalid_client_credentials"))

    access.sort(key=lambda r: r["@timestamp"])
    events.sort(key=lambda r: r["@timestamp"])
    return access, events


# --------------------------------------------------------------------------------------
# Ground truth
# --------------------------------------------------------------------------------------
INTRODUCED_IN = {"KC-BC-001": "26.6.3", "KC-BC-002": "26.0.0", "KC-BC-003": "26.4.3", "KC-BC-004": "26.0.0"}

SCENARIOS = {
    "s-26.5-to-26.6.3": ("26.5.0", "26.6.3"),
    "s-25.0-to-26.6.3": ("25.0.6", "26.6.3"),
    "s-26.3-to-26.5": ("26.3.0", "26.5.0"),
}

ANONYMOUS_PLANTS = {
    "KC-BC-002": {"confidence": "medium", "attribution": "none"},
    "KC-BC-003": {"confidence": "high", "attribution": "none"},
}


def applicable(bc_id: str, source: str, target: str) -> bool:
    intro = Version(INTRODUCED_IN[bc_id])
    return Version(source) < intro <= Version(target)


def build_expected(specs: list[Spec]) -> dict:
    out = {"generated_by": "scripts/generate_dataset.py", "log_origins": ["synthetic-fixture"], "scenarios": {}}
    for sid, (src, tgt) in SCENARIOS.items():
        expected = []
        flagged = set()
        for s in specs:
            for bc_id, meta in s.plant.items():
                if applicable(bc_id, src, tgt):
                    expected.append({"bc_id": bc_id, "client_id": s.client_id, "confidence": meta["confidence"],
                                     "attribution": meta.get("attribution", "explicit")})
                    flagged.add(s.client_id)
        for bc_id, meta in ANONYMOUS_PLANTS.items():
            if applicable(bc_id, src, tgt):
                expected.append({"bc_id": bc_id, "client_id": "anonymous", **meta})
        expected.append({"bc_id": "KC-BC-005", "client_id": "anonymous", "confidence": "high", "attribution": "none"})
        expected.sort(key=lambda e: (e["bc_id"], e["client_id"]))
        out["scenarios"][sid] = {
            "source_version": src,
            "target_version": tgt,
            "expected": expected,
            "must_not_flag": sorted(s.client_id for s in specs if s.client_id not in flagged),
        }
    return out


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=str(Path(__file__).resolve().parent.parent / "data"))
    args = ap.parse_args()
    data = Path(args.data_dir)

    specs = build_specs()
    write_json(data / "realms" / "enterprise-realm.json", build_realm(specs))
    write_json(data / "realms" / "client-inventory.json", build_inventory(specs))
    access, events = build_logs(specs)
    write_jsonl(data / "logs" / "access-logs.jsonl", access)
    write_jsonl(data / "logs" / "keycloak-events.jsonl", events)
    write_json(data / "scenarios" / "expected-findings.json", build_expected(specs))
    print(f"clients={len(specs)} access_records={len(access)} event_records={len(events)}")


if __name__ == "__main__":
    main()
