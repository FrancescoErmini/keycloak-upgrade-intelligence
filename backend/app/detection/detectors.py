"""Closed detector registry: the ONLY vocabulary in which a rule can express detection.

Why: an LLM asked to "write a detection rule" produces a different regex, field name or
label every time for the same filter (e.g. "logout-redirect", "legacy_logout",
"Deprecated logout param" ...). Here the LLM can only *choose* a detector id from this
registry and fill typed, enumerated parameters. Conditions, finding category and
labels are defined once, in code, so the same filter always yields the same rule
fingerprint and the same label.

Adding a detector is a reviewed code change (bump REGISTRY_VERSION). When no detector
fits, the LLM returns `detector: "none"` plus a free-text `proposed_detector`, which
goes to the review queue instead of becoming an ad-hoc rule.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..utils import stable_id

REGISTRY_VERSION = "2026-11-04.1"

# ---- fixed taxonomies ---------------------------------------------------------------------
CHANGE_TYPES = ("breaking", "notable", "deprecated", "removed", "end-of-life")
SEVERITIES = ("critical", "high", "medium", "low", "info")
IMPACT_AREAS = (
    "redirect-uri-validation", "http-endpoints", "protocol-token-mapping", "client-configuration",
    "authentication-flows", "saml", "identity-brokering", "admin-api", "account-console", "themes-ui",
    "server-configuration", "database-storage", "clustering-caching", "operator-kubernetes",
    "spi-extensions", "observability", "security-hardening", "other",
)
CATEGORY_LABELS = {
    "redirect-uri-validation": "Redirect URI validation",
    "deprecated-http-endpoints": "Deprecated HTTP endpoints",
    "protocol-token-mapping": "Protocol / token mapping",
    "client-configuration": "Client configuration",
    "keycloak-events": "Keycloak events",
    "unattributed-calls": "Unattributed calls (control)",
    "manual-review": "Manual review",
}

# Endpoints are identified by id; the LLM never writes a path regex.
ENDPOINTS: dict[str, str] = {
    "oidc-auth": r"/realms/[^/]+/protocol/openid-connect/auth$",
    "oidc-token": r"/realms/[^/]+/protocol/openid-connect/token$",
    "oidc-logout": r"/realms/[^/]+/protocol/openid-connect/logout/?$",
    "oidc-userinfo": r"/realms/[^/]+/protocol/openid-connect/userinfo$",
    "oidc-certs": r"/realms/[^/]+/protocol/openid-connect/certs$",
    "oidc-introspect": r"/realms/[^/]+/protocol/openid-connect/token/introspect$",
    "oidc-revoke": r"/realms/[^/]+/protocol/openid-connect/revoke$",
    "oidc-par": r"/realms/[^/]+/protocol/openid-connect/ext/par/request$",
    "oidc-device": r"/realms/[^/]+/protocol/openid-connect/auth/device$",
    "oidc-ciba": r"/realms/[^/]+/protocol/openid-connect/ext/ciba/auth$",
    "oidc-discovery": r"/realms/[^/]+/\.well-known/openid-configuration$",
    "saml": r"/realms/[^/]+/protocol/saml(/.*)?$",
    "account": r"/realms/[^/]+/account(/.*)?$",
    "admin-api": r"^/admin/realms(/.*)?$",
}
GRANTS = ("authorization_code", "implicit", "password", "client_credentials", "bearer-only", "saml")
MAPPER_TYPES = (
    "oidc-usermodel-realm-role-mapper", "oidc-usermodel-client-role-mapper", "oidc-usermodel-attribute-mapper",
    "oidc-group-membership-mapper", "oidc-hardcoded-claim-mapper", "oidc-audience-mapper",
)
_IDENT = re.compile(r"^[A-Za-z0-9_.\-]{1,80}$")
_EVENT = re.compile(r"^[A-Z][A-Z0-9_]{1,60}$")

CLIENT_ACTIVITY = {"any": [
    {"field": "url.path", "op": "regex", "value": "/protocol/openid-connect/(auth|token)$|/protocol/saml"},
    {"field": "event.action", "op": "in", "value": ["LOGIN", "CODE_TO_TOKEN", "CLIENT_LOGIN", "REFRESH_TOKEN"]},
]}


@dataclass(frozen=True)
class Param:
    name: str
    kind: str  # enum | enum_list | ident | event
    choices: tuple[str, ...] = ()
    grounded: bool = False  # value must literally appear in the documentation entry


@dataclass(frozen=True)
class Detector:
    id: str
    label: str
    category: str
    source: str  # static | runtime | none
    description: str
    params: tuple[Param, ...] = ()
    compile: Callable[[dict], dict | None] = field(default=lambda p: None, repr=False)

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS[self.category]


def _redirect_wildcard(_: dict) -> dict:
    return {
        # a wildcard after at least one host character; the full wildcard "https://*" stays valid
        "static": {"target": "client", "condition": {
            "field": "redirect_uris", "op": "any_regex", "value": r"^[A-Za-z][A-Za-z0-9+.\-]*://[^/?#*]+\*"}},
        "runtime": {"mode": "corroborate", "condition": CLIENT_ACTIVITY},
    }


def _mapper(p: dict) -> dict:
    return {
        "static": {"target": "client", "condition": {"field": "protocol_mappers", "op": "any_item", "where": {"all": [
            {"field": "type", "op": "in", "value": list(p["mapper_types"])},
            {"field": "multivalued", "op": "eq", "value": False},
        ]}}},
        "runtime": {"mode": "corroborate", "condition": CLIENT_ACTIVITY},
    }


def _grant(p: dict) -> dict:
    return {"static": {"target": "client", "condition": {"field": "grant_types", "op": "contains", "value": p["grant"]}},
            "runtime": {"mode": "corroborate", "condition": CLIENT_ACTIVITY}}


def _attribute(p: dict) -> dict:
    return {"static": {"target": "client", "condition": {"field": f"attributes.{p['attribute']}", "op": "exists", "value": True}}}


def _query_param(p: dict) -> dict:
    runtime: dict[str, Any] = {"mode": "detect", "condition": {"all": [
        {"field": "url.path", "op": "regex", "value": ENDPOINTS[p["endpoint"]]},
        {"field": "url.query", "op": "has_param", "value": p["param"]},
    ]}}
    if p["param"] in ("redirect_uri", "post_logout_redirect_uri"):
        runtime["attribution"] = {"infer_from_params": [p["param"]]}
    return {"runtime": runtime}


def _endpoint(p: dict) -> dict:
    return {"runtime": {"mode": "detect", "condition": {"field": "url.path", "op": "regex", "value": ENDPOINTS[p["endpoint"]]}}}


def _non_normalized(_: dict) -> dict:
    return {"runtime": {"mode": "detect", "condition": {"field": "url.path", "op": "regex", "value": r"//|/\.\.?(/|$)"}}}


def _event(p: dict) -> dict:
    return {"runtime": {"mode": "detect", "condition": {"field": "event.action", "op": "eq", "value": p["event_type"]}}}


DETECTORS: dict[str, Detector] = {d.id: d for d in (
    Detector("client.redirect_uri.hostname_wildcard", "Wildcard in redirect URI hostname", "redirect-uri-validation",
             "static", "A valid redirect URI has a '*' wildcard inside or right after the host name (e.g. https://example.com*).",
             compile=_redirect_wildcard),
    Detector("client.protocol_mapper.single_valued", "Single-valued protocol mapper", "protocol-token-mapping", "static",
             "A client protocol mapper of the given types has the Multivalued setting disabled.",
             (Param("mapper_types", "enum_list", MAPPER_TYPES),), _mapper),
    Detector("client.grant.enabled", "Grant type enabled on client", "client-configuration", "static",
             "Clients that have the given grant / flow enabled.", (Param("grant", "enum", GRANTS),), _grant),
    Detector("client.attribute.present", "Client attribute configured", "client-configuration", "static",
             "Clients that set a specific client attribute (attribute key copied from the documentation).",
             (Param("attribute", "ident", grounded=True),), _attribute),
    Detector("http.endpoint.query_param", "Query parameter on endpoint", "deprecated-http-endpoints", "runtime",
             "HTTP requests to the given endpoint carrying the given query parameter.",
             (Param("endpoint", "enum", tuple(ENDPOINTS)), Param("param", "ident", grounded=True)), _query_param),
    Detector("http.endpoint.called", "Endpoint called", "deprecated-http-endpoints", "runtime",
             "HTTP requests to the given (deprecated/removed) endpoint.", (Param("endpoint", "enum", tuple(ENDPOINTS)),), _endpoint),
    Detector("http.path.non_normalized", "Non-normalized request path", "deprecated-http-endpoints", "runtime",
             "HTTP requests whose path contains '//' or dot segments ('/./', '/../').", compile=_non_normalized),
    Detector("event.type", "Keycloak event type observed", "keycloak-events", "runtime",
             "Keycloak events (org.keycloak.events) of the given type.", (Param("event_type", "event", grounded=True),), _event),
    Detector("none", "Not detectable from realm/logs", "manual-review", "none",
             "Server-side, SPI, operator, theme or database change: not observable in client config or HTTP logs."),
)}
DETECTOR_IDS = tuple(DETECTORS)


class DetectorError(ValueError):
    pass


def canonical_params(detector_id: str, raw: dict | None, entry_text: str = "") -> dict:
    """Keep only the parameters the detector declares, normalized; raise on invalid values."""
    det = DETECTORS.get(detector_id)
    if det is None:
        raise DetectorError(f"unknown detector {detector_id!r}")
    raw = raw or {}
    text = entry_text.lower()
    out: dict[str, Any] = {}
    for p in det.params:
        v = raw.get(p.name)
        if v in (None, "", []):
            raise DetectorError(f"{detector_id}: missing parameter {p.name!r}")
        if p.kind == "enum":
            v = str(v).strip().lower()
            if v not in p.choices:
                raise DetectorError(f"{detector_id}: {p.name}={v!r} not in {p.choices}")
        elif p.kind == "enum_list":
            v = sorted({str(x).strip().lower() for x in (v if isinstance(v, list) else [v])})
            bad = [x for x in v if x not in p.choices]
            if bad:
                raise DetectorError(f"{detector_id}: {p.name} values {bad} not allowed")
        elif p.kind == "ident":
            v = str(v).strip().strip("`")
            if not _IDENT.match(v):
                raise DetectorError(f"{detector_id}: {p.name}={v!r} is not a plain identifier")
        elif p.kind == "event":
            v = str(v).strip().upper()
            if not _EVENT.match(v):
                raise DetectorError(f"{detector_id}: {p.name}={v!r} is not an event type")
        if p.grounded and entry_text and str(v).lower() not in text:
            raise DetectorError(f"{detector_id}: {p.name}={v!r} does not appear in the documentation entry")
        out[p.name] = v
    return out


def fingerprint(detector_id: str, params: dict) -> str:
    """Same detector + same canonical params => same fingerprint => same filter and label."""
    return f"{detector_id}#{stable_id(params, length=10)}" if params else detector_id


def compile_detection(detector_id: str, params: dict) -> dict | None:
    return DETECTORS[detector_id].compile(params)


def catalog_for_prompt() -> list[dict]:
    return [{"id": d.id, "source": d.source, "description": d.description,
             "params": {p.name: (list(p.choices) if p.choices else p.kind) for p in d.params}}
            for d in DETECTORS.values()]
