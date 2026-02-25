from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

import httpx

from .utils import extract_json_object


@dataclass
class LLMJSONResult:
    payload: dict[str, Any]
    latency_ms: int


class OpenAICompatClient:
    def __init__(self, endpoint: str, api_key: str | None = None, timeout_seconds: float = 10.0):
        if not endpoint:
            raise ValueError("Endpoint is required for openai mode")
        self.endpoint = self._normalize_endpoint(endpoint)
        self.api_key = api_key
        self.timeout_seconds = timeout_seconds

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        endpoint = endpoint.rstrip("/")
        if endpoint.endswith("/chat/completions"):
            return endpoint
        if endpoint.endswith("/v1"):
            return f"{endpoint}/chat/completions"
        return f"{endpoint}/v1/chat/completions"

    def classify_json(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.0,
    ) -> LLMJSONResult:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": model,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        start = time.monotonic()
        with httpx.Client(timeout=self.timeout_seconds) as client:
            response = client.post(self.endpoint, headers=headers, json=payload)
            response.raise_for_status()
            data = response.json()

        latency_ms = int((time.monotonic() - start) * 1000)

        choices = data.get("choices") or []
        if not choices:
            raise RuntimeError("No choices returned by model")

        message = choices[0].get("message") or {}
        content = message.get("content")
        if content is None:
            raise RuntimeError("Model output missing message content")

        return LLMJSONResult(payload=extract_json_object(content), latency_ms=latency_ms)
