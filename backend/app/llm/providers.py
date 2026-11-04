"""LLM providers.

The LLM is used only by the manual sync job, to map documentation entries onto the
closed detector registry, and to phrase explanations. Detection never depends on it.

All providers expose `complete_json(messages, schema, name)`, which must return an
object conforming to the JSON schema (OpenAI Structured Outputs with strict=true;
Ollama `format=<schema>`), plus `explain(...)` for free text.
"""
from __future__ import annotations

import json
from typing import Protocol

import requests

from . import prompts


class LLMProvider(Protocol):
    name: str
    model: str

    def available(self) -> bool: ...
    def complete_json(self, messages: list[dict], schema: dict, name: str) -> dict | None: ...
    def explain(self, finding: dict, passages: list[dict]) -> str | None: ...


class NoLLM:
    name = "none"
    model = "none"

    def available(self) -> bool:
        return False

    def complete_json(self, messages, schema, name):
        return None

    def explain(self, finding, passages):
        return None


class OpenAIProvider:
    """OpenAI Chat Completions with Structured Outputs (json_schema, strict)."""

    name = "openai"

    def __init__(self, api_key: str, model: str, base_url: str = "https://api.openai.com/v1",
                 temperature: str = "0", seed: int | None = 7, timeout: int = 120) -> None:
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.temperature = temperature
        self.seed = seed
        self.timeout = timeout

    def available(self) -> bool:
        return bool(self.api_key)

    def _chat(self, messages: list[dict], response_format: dict | None = None) -> str:
        body: dict = {"model": self.model, "messages": messages}
        if self.temperature != "":
            body["temperature"] = float(self.temperature)
        if self.seed is not None:
            body["seed"] = self.seed
        if response_format:
            body["response_format"] = response_format
        r = requests.post(f"{self.base_url}/chat/completions", json=body, timeout=self.timeout,
                          headers={"Authorization": f"Bearer {self.api_key}"})
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
        if msg.get("refusal"):
            raise RuntimeError(f"model refusal: {msg['refusal']}")
        return msg.get("content") or ""

    def complete_json(self, messages, schema, name):
        fmt = {"type": "json_schema", "json_schema": {"name": name, "strict": True, "schema": schema}}
        return json.loads(self._chat(messages, fmt))

    def explain(self, finding, passages):
        try:
            return self._chat([{"role": "user", "content": prompts.explanation(finding, passages)}]).strip() or None
        except (requests.RequestException, RuntimeError, KeyError):
            return None


class OllamaProvider:
    """Local model via Ollama (no API cost). `format` accepts a JSON schema."""

    name = "ollama"

    def __init__(self, url: str, model: str, timeout: int = 300) -> None:
        self.url = url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def available(self) -> bool:
        try:
            return requests.get(f"{self.url}/api/tags", timeout=3).ok
        except requests.RequestException:
            return False

    def _chat(self, messages, fmt=None) -> str:
        body = {"model": self.model, "messages": messages, "stream": False, "options": {"temperature": 0, "seed": 7}}
        if fmt is not None:
            body["format"] = fmt
        r = requests.post(f"{self.url}/api/chat", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()["message"]["content"]

    def complete_json(self, messages, schema, name):
        return json.loads(self._chat(messages, schema))

    def explain(self, finding, passages):
        try:
            return self._chat([{"role": "user", "content": prompts.explanation(finding, passages)}]).strip() or None
        except requests.RequestException:
            return None


def get_provider(settings) -> LLMProvider:
    if settings.llm_provider == "openai":
        return OpenAIProvider(settings.openai_api_key, settings.openai_model, settings.openai_base_url,
                              settings.llm_temperature, settings.llm_seed)
    if settings.llm_provider == "ollama":
        return OllamaProvider(settings.ollama_url, settings.ollama_model)
    return NoLLM()
