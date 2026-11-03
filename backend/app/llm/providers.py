"""LLM providers. The LLM is only used to *propose* rules and to phrase explanations.

Detection never depends on it: approved JSON rules are executed deterministically.
"""
from __future__ import annotations

import json
from typing import Protocol

import requests

from . import prompts


class LLMProvider(Protocol):
    name: str

    def available(self) -> bool: ...
    def extract_rule(self, section: dict) -> dict | None: ...
    def explain(self, finding: dict, passages: list[dict]) -> str | None: ...


class NoLLM:
    name = "none"

    def available(self) -> bool:
        return False

    def extract_rule(self, section: dict) -> dict | None:
        return None

    def explain(self, finding: dict, passages: list[dict]) -> str | None:
        return None


class OllamaProvider:
    """Local model via Ollama: no API cost, data stays on the host."""

    name = "ollama"

    def __init__(self, url: str, model: str, timeout: int = 120) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def available(self) -> bool:
        try:
            return requests.get(f"{self.url}/api/tags", timeout=3).ok
        except requests.RequestException:
            return False

    def _generate(self, prompt: str, json_mode: bool) -> str:
        body = {"model": self.model, "prompt": prompt, "stream": False, "options": {"temperature": 0}}
        if json_mode:
            body["format"] = "json"
        r = requests.post(f"{self.url}/api/generate", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("response", "")

    def extract_rule(self, section: dict) -> dict | None:
        try:
            return json.loads(self._generate(prompts.rule_extraction(section), json_mode=True))
        except (requests.RequestException, ValueError):
            return None

    def explain(self, finding: dict, passages: list[dict]) -> str | None:
        try:
            return self._generate(prompts.explanation(finding, passages), json_mode=False).strip() or None
        except requests.RequestException:
            return None


def get_provider(settings) -> LLMProvider:
    if settings.llm_provider == "ollama":
        return OllamaProvider(settings.ollama_url, settings.ollama_model)
    return NoLLM()
