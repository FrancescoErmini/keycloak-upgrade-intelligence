"""Prompt templates. Both prompts force the model to stay grounded in the given text."""
from __future__ import annotations

import json

PROMPT_VERSION = "2026-11-04.3"

RULE_SYSTEM = """You are a senior Keycloak engineer preparing a production upgrade.

You receive ONE entry of the official Keycloak Upgrading Guide. Work out how an operator could find out,
on a live Keycloak installation, whether this change affects them and which clients (applications) are impacted.

Think freely, like an SRE writing an upgrade checklist. Consider every place where the change could leave a trace:
the realm export (client configuration, redirect URIs, protocol mappers, flows), HTTP access logs, Keycloak event logs,
server logs, server info (features, installed SPI providers), server startup options, custom extensions, themes,
the database, Kubernetes/Operator resources, the client applications themselves.

Return one item in "checks" for every distinct verification. If the change can be observed in several places,
return several checks (e.g. one on the realm export and one on the access log). Mark the data source of EVERY check,
even when it is something like server_info, server_config or custom_extensions: checks are filtered later by the data
sources actually available, so do not drop a check because it looks hard to run.

For each check:
- say what to look at, how to look at it, and what result means "impacted";
- set "scope" to "client" when the check can point at specific clients, otherwise "realm" or "server";
- if the check matches one of the automated detectors provided, set "detector" and fill its params
  (unused params null); otherwise set "detector" to "none" and describe the check precisely enough for a human;
- copy in "evidence_quote" a sentence of the entry, verbatim, that justifies the check.

Attach a detector only when it selects exactly the clients or requests affected by the change. A detector that would
also flag many unaffected clients (for example every client with a common grant type) is wrong: use "none" and
describe the precise check instead. Use log.message.contains only for a message that the entry says Keycloak writes
to its log.

Stay grounded in the entry: do not invent endpoints, parameters, options or versions it does not mention.
If the change has no observable effect at all (e.g. purely internal refactoring), return an empty "checks" list and
say why in "analysis".
Write "analysis" first: briefly reason about what changes for clients and where it shows up, then fill the rest."""


def rule_user_message(entry: dict, registry: list[dict], examples: list[dict], data_sources: dict) -> str:
    return json.dumps({
        "data_sources": data_sources,
        "automated_detectors": registry,
        "examples": examples,
        "entry": {"version": entry["version"], "upgrading_from": entry.get("from_version"),
                  "category_in_guide": entry["category"], "title": entry["title"], "text": entry["text"][:6000]},
    }, ensure_ascii=False, indent=1)


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
