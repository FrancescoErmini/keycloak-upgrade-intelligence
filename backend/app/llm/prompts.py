"""Prompt templates. Both prompts force the model to stay grounded in the given text."""
from __future__ import annotations

import json

PROMPT_VERSION = "2026-11-04.1"

RULE_SYSTEM = """You classify one entry of the Keycloak Upgrading Guide and map it onto a CLOSED registry of detectors.
You never write regular expressions, field names or labels: you only choose a detector id from the registry and fill
its parameters with the allowed values. Rules:
1. Use only the entry text. Never invent endpoints, parameters, options or versions.
2. "source_quote" must be ONE sentence copied verbatim (character by character) from the entry text.
3. If the change cannot be observed in a client configuration (realm export) or in HTTP access logs / Keycloak events
   (e.g. SPI/Java API, operator, database, theme, server option changes), use detector "none" and decision
   "not_detectable" (or "not_client_impacting" when no application is affected).
4. If the change is detectable but no detector fits, use detector "none", decision "not_detectable" and describe
   the missing detector in "proposed_detector" (short snake_case name). Never stretch a detector to fit.
5. Parameters not used by the chosen detector must be null. Identifier parameters (param, attribute, event_type) must
   appear literally in the entry text.
6. Same kind of change => same detector and same parameters: follow the examples."""


def rule_user_message(entry: dict, registry: list[dict], examples: list[dict]) -> str:
    return json.dumps({
        "detector_registry": registry,
        "examples": examples,
        "entry": {"version": entry["version"], "from_version": entry.get("from_version"),
                  "category_in_guide": entry["category"], "title": entry["title"], "text": entry["text"][:6000]},
    }, ensure_ascii=False)


def explanation(finding: dict, passages: list[dict]) -> str:
    ctx = "\n\n".join(f"[{p['bc_id']} | {p['section_anchor']}] {p['text']}" for p in passages)
    evidence = json.dumps(finding.get("evidence", [])[:5], ensure_ascii=False)
    return f"""Explain to an application owner why their Keycloak client is impacted by an upgrade.
Rules: cite the breaking change id {finding['bc_id']} explicitly; use only the documentation passages and evidence below;
do not mention behaviours that are not in the passages; answer in at most 6 sentences; end with the remediation.

Client: {finding['client_id']}  Upgrade: {finding['source_version']} -> {finding['target_version']}
Remediation: {finding.get('remediation')}
Evidence: {evidence}

Documentation passages:
{ctx}
"""
