"""Rule model: condition evaluation and grounding validation.

Rules are built from the detector registry (detectors.py) and indexed in kc-bc-rules.
Conditions form a tiny, closed DSL so that a rule proposed by an LLM can only
refer to fields and operators that the analyzers actually know about.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Any
from urllib.parse import parse_qs

from ..utils import get_path, parse_version

SEVERITIES = ("critical", "high", "medium", "low", "info")
KINDS = ("breaking-change", "control")
RUNTIME_MODES = ("detect", "corroborate", "aggregate")
OPS = ("eq", "ne", "in", "regex", "any_regex", "exists", "contains", "has_param", "any_item", "gte", "lte")

CLIENT_FIELDS = {
    "client_id", "protocol", "client_type", "enabled", "public_client", "bearer_only", "grant_types",
    "redirect_uris", "post_logout_redirect_uris", "web_origins", "root_url", "protocol_mappers",
    "attributes", "redirect_uri_analysis",
}
MAPPER_FIELDS = {"name", "type", "protocol", "claim_name", "multivalued"}
REDIRECT_FIELDS = {"uri", "scheme", "authority", "host_wildcard", "path_wildcard", "kind"}
LOG_FIELDS = {
    "url.path", "url.query", "url.original", "url.query_param_names", "http.request.method",
    "http.response.status_code", "event.kind", "event.action", "event.outcome", "client_id",
    "client_identified", "keycloak.realm", "keycloak.error", "message",
}


@lru_cache(maxsize=256)
def _rx(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def query_params(query: str | None) -> dict[str, list[str]]:
    return parse_qs(query or "", keep_blank_values=True)


def evaluate(cond: dict, doc: dict) -> bool:
    if "all" in cond:
        return all(evaluate(c, doc) for c in cond["all"])
    if "any" in cond:
        return any(evaluate(c, doc) for c in cond["any"])
    if "not" in cond:
        return not evaluate(cond["not"], doc)

    op, field, value = cond["op"], cond["field"], cond.get("value")
    actual = get_path(doc, field)
    if op == "eq":
        return actual == value
    if op == "ne":
        return actual != value
    if op == "in":
        return actual in value
    if op == "exists":
        return (actual is not None) == bool(value if value is not None else True)
    if op == "regex":
        return isinstance(actual, str) and _rx(value).search(actual) is not None
    if op == "any_regex":
        return isinstance(actual, list) and any(isinstance(a, str) and _rx(value).search(a) for a in actual)
    if op == "contains":
        return isinstance(actual, (list, str)) and value in actual
    if op == "has_param":
        return value in query_params(actual if isinstance(actual, str) else None)
    if op == "any_item":
        return isinstance(actual, list) and any(isinstance(i, dict) and evaluate(cond["where"], i) for i in actual)
    if op in ("gte", "lte"):
        if actual is None:
            return False
        return actual >= value if op == "gte" else actual <= value
    raise ValueError(f"unsupported operator {op}")


def matching_values(cond: dict, doc: dict) -> list[Any]:
    """Values that made a static condition true (used as human-readable evidence)."""
    out: list[Any] = []
    if "all" in cond or "any" in cond:
        for c in cond.get("all", []) + cond.get("any", []):
            out.extend(matching_values(c, doc))
        return out
    if "not" in cond:
        return out
    actual = get_path(doc, cond["field"])
    if cond["op"] == "any_regex" and isinstance(actual, list):
        out.extend(a for a in actual if isinstance(a, str) and _rx(cond["value"]).search(a))
    elif cond["op"] == "any_item" and isinstance(actual, list):
        out.extend(i for i in actual if isinstance(i, dict) and evaluate(cond["where"], i))
    elif evaluate(cond, doc):
        out.append({cond["field"]: actual})
    return out


# ------------------------------------------------------------------------------------------
# Grounding validation
# ------------------------------------------------------------------------------------------
def _walk(cond: dict, scope: str, errors: list[str], params: list[str]) -> None:
    if not isinstance(cond, dict):
        errors.append("condition must be an object")
        return
    for key in ("all", "any"):
        if key in cond:
            if not isinstance(cond[key], list) or not cond[key]:
                errors.append(f"'{key}' must be a non-empty list")
                return
            for c in cond[key]:
                _walk(c, scope, errors, params)
            return
    if "not" in cond:
        _walk(cond["not"], scope, errors, params)
        return
    op, field = cond.get("op"), cond.get("field")
    if op not in OPS:
        errors.append(f"unknown operator {op!r}")
        return
    allowed = {"client": CLIENT_FIELDS, "log": LOG_FIELDS, "mapper": MAPPER_FIELDS, "redirect": REDIRECT_FIELDS}[scope]
    if field not in allowed and not (scope == "client" and str(field).startswith("attributes.")):
        errors.append(f"field {field!r} is not allowed in {scope} conditions")
    if op in ("regex", "any_regex"):
        try:
            re.compile(cond.get("value", ""))
        except re.error as exc:
            errors.append(f"invalid regex {cond.get('value')!r}: {exc}")
    if op == "has_param":
        params.append(str(cond.get("value")))
    if op == "any_item":
        sub = {"protocol_mappers": "mapper", "redirect_uri_analysis": "redirect"}.get(field)
        if sub is None or "where" not in cond:
            errors.append(f"any_item on {field!r} is not supported")
        else:
            _walk(cond["where"], sub, errors, params)


def validate_rule(rule: dict) -> list[str]:
    """Structural validation of an indexed rule document (compiled detection must use the DSL).

    Grounding against the documentation is checked earlier, when the rule spec is built
    (ingestion.rule_extraction.validate_spec).
    """
    errors: list[str] = []
    for key in ("bc_id", "title", "kind", "category", "severity", "remediation"):
        if not rule.get(key):
            errors.append(f"missing field {key!r}")
    if errors:
        return errors
    if rule["kind"] not in KINDS:
        errors.append(f"invalid kind {rule['kind']!r}")
    if rule["severity"] not in SEVERITIES:
        errors.append(f"invalid severity {rule['severity']!r}")
    if rule["kind"] == "breaking-change" and parse_version(rule.get("introduced_in")) is None:
        errors.append(f"invalid introduced_in {rule.get('introduced_in')!r}")
    from .detectors import DATA_SOURCES

    for check in rule.get("checks") or []:
        if check.get("data_source") not in DATA_SOURCES:
            errors.append(f"check {check.get('check_id')}: invalid data_source {check.get('data_source')!r}")
        detection = check.get("detection")
        if not detection:
            continue  # manual check: documented, never executed
        params: list[str] = []
        if detection.get("static"):
            if detection["static"].get("target") != "client":
                errors.append("static.target must be 'client'")
            _walk(detection["static"].get("condition", {}), "client", errors, params)
        if detection.get("runtime"):
            if detection["runtime"].get("mode") not in RUNTIME_MODES:
                errors.append(f"invalid runtime.mode {detection['runtime'].get('mode')!r}")
            if detection["runtime"].get("mode") == "corroborate" and not detection.get("static"):
                errors.append("a 'corroborate' runtime part requires a static part")
            _walk(detection["runtime"].get("condition", {}), "log", errors, params)
    return errors


def applicable_rules(rules: list[dict], source: str, target: str) -> list[dict]:
    from ..utils import is_applicable

    return [r for r in rules if r.get("status") == "approved" and
            (r["kind"] == "control" or is_applicable(r.get("introduced_in"), source, target))]
