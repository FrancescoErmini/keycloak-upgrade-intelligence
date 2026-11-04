"""Request format of the OpenAI provider (no network: requests.post is replaced)."""
import json

from app.ingestion.rule_extraction import response_schema
from app.llm import providers
from app.llm.providers import OpenAIProvider


class Resp:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self.payload


def test_structured_output_request(monkeypatch):
    sent = {}

    def fake_post(url, json=None, headers=None, timeout=None):
        sent.update(url=url, body=json, headers=headers)
        return Resp({"choices": [{"message": {"content": '{"detector": "none"}'}}]})

    monkeypatch.setattr(providers.requests, "post", fake_post)
    p = OpenAIProvider("sk-test", "gpt-4.1-mini", temperature="0", seed=7)
    out = p.complete_json([{"role": "user", "content": "x"}], response_schema(), "keycloak_detection_rule")
    assert out == {"detector": "none"}
    assert sent["url"] == "https://api.openai.com/v1/chat/completions"
    assert sent["headers"]["Authorization"] == "Bearer sk-test"
    body = sent["body"]
    assert body["model"] == "gpt-4.1-mini" and body["temperature"] == 0.0 and body["seed"] == 7
    fmt = body["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["strict"] is True
    assert fmt["json_schema"]["schema"]["properties"]["detector"]["enum"]


def test_temperature_can_be_omitted_and_key_required(monkeypatch):
    sent = {}
    monkeypatch.setattr(providers.requests, "post", lambda url, json=None, headers=None, timeout=None:
                        (sent.update(body=json), Resp({"choices": [{"message": {"content": "{}"}}]}))[1])
    OpenAIProvider("k", "o4-mini", temperature="").complete_json([], {"type": "object"}, "n")
    assert "temperature" not in sent["body"]
    assert OpenAIProvider("", "gpt-4.1-mini").available() is False
