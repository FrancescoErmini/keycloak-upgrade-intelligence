"""Prompt templates. Both prompts force the model to stay grounded in the given text."""
from __future__ import annotations

import json

ALLOWED_FIELDS_HINT = (
    "client fields: client_id, protocol, client_type, enabled, public_client, bearer_only, grant_types, "
    "redirect_uris, post_logout_redirect_uris, web_origins, root_url, protocol_mappers[type,multivalued,claim_name]; "
    "log fields: url.path, url.query, http.request.method, http.response.status_code, event.action, client_id, client_identified"
)


def rule_extraction(section: dict) -> str:
    return f"""You convert one section of the Keycloak upgrading guide into a JSON detection rule.
Use ONLY information present in the section. Do not invent endpoints, parameters or versions.
Return a JSON object with keys: title, category, introduced_in, severity (critical|high|medium|low|info),
source_quote (a sentence copied VERBATIM from the section), evidence_terms (words copied from the section),
detection (object with optional "static" {{target:"client", condition}} and "runtime" {{mode:"detect"|"corroborate", condition}}),
remediation.
A condition is {{"all":[...]}}, {{"any":[...]}}, {{"not":cond}} or {{"field","op","value"}} with op in
eq, ne, in, regex, any_regex, exists, contains, has_param, any_item (with "where").
Allowed fields -> {ALLOWED_FIELDS_HINT}.
If the section cannot be turned into a rule, return {{"skip": true}}.

Section version: {section.get('version')}
Section title: {section.get('title')}
Section text:
\"\"\"{section.get('text')}\"\"\"
"""


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
