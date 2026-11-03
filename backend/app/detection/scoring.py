"""Confidence and risk scoring.

Confidence expresses how sure we are that the client is really affected:
  * static evidence only ............................ 0.70
  * static evidence corroborated by runtime traffic ... 0.95
  * runtime detection: 1 hit 0.70, 2 hits 0.80, >=3 hits 0.90
  * client attributed by inference (redirect URI match) x0.85
  * client disabled in the realm ...................... x0.50
  * controls (deterministic aggregates) ............... 1.00
"""
from __future__ import annotations

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25, "info": 0.1}
CRITICALITY_WEIGHT = {"critical": 1.0, "high": 0.85, "medium": 0.7, "low": 0.5}


def runtime_confidence(hits: int) -> float:
    if hits <= 0:
        return 0.0
    return {1: 0.70, 2: 0.80}.get(hits, 0.90)


def confidence(*, static: bool, corroborated: bool, runtime_hits: int, inferred: bool,
               client_enabled: bool | None, control: bool = False) -> float:
    if control:
        return 1.0
    if static:
        c = 0.95 if corroborated else 0.70
    else:
        c = runtime_confidence(runtime_hits)
    if inferred:
        c *= 0.85
    if client_enabled is False:
        c *= 0.5
    return round(c, 3)


def confidence_label(c: float) -> str:
    if c >= 0.85:
        return "high"
    if c >= 0.6:
        return "medium"
    return "low"


def risk_score(severity: str, conf: float, criticality: str | None) -> float:
    return round(100 * SEVERITY_WEIGHT.get(severity, 0.5) * conf * CRITICALITY_WEIGHT.get(criticality or "medium", 0.7), 1)


def readiness(findings: list[dict]) -> str:
    bc = [f for f in findings if f["kind"] == "breaking-change"]
    if any(f["severity"] == "critical" and f["confidence_label"] == "high" and f["client_identified"] for f in bc):
        return "blocked"
    if bc:
        return "review-required"
    return "ready"
