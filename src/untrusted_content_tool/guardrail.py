from __future__ import annotations

import re
import time
from collections import Counter

from .llm_client import OpenAICompatClient
from .models import GuardrailConfig, GuardrailResult
from .utils import clip

_PROMPT_INJECTION_PATTERNS = [
    r"ignore\s+(all|any|previous|prior)",
    r"disregard\s+(all|any|previous|prior)",
    r"you\s+are\s+now",
    r"system\s*:",
    r"developer\s+mode",
    r"override\s+(instructions|rules)",
    r"call\s+the\s+tool",
    r"run_command",
    r"write_file",
    r"send_http_request",
    r"read_system_file",
]

_JAILBREAK_PATTERNS = [
    r"jailbreak",
    r"bypass\s+safety",
    r"do\s+anything\s+now",
    r"dan\b",
]

_HARMFUL_PATTERNS = [
    r"exfiltrat",
    r"steal\s+credentials",
    r"drop\s+table",
    r"rm\s+-rf",
    r"curl\s+[^\s]+\s*\|\s*sh",
]

_PII_PATTERNS = [
    r"aws_access_key_id",
    r"~/.aws/credentials",
    r"-----begin\s+private\s+key-----",
    r"ssn",
    r"api[_-]?key",
]

_GUARDRAIL_SYSTEM_PROMPT = """
You are a security classifier for untrusted text.
Return only JSON in this exact shape:
{
  "prompt_injection": 0.0,
  "jailbreak": 0.0,
  "harmful_content": 0.0,
  "pii_exposure": 0.0,
  "safe": 0.0
}
Scores must be floats in [0,1].
""".strip()


class GuardrailEngine:
    def __init__(self, config: GuardrailConfig):
        self.config = config

    def classify(self, content: str) -> GuardrailResult:
        start = time.monotonic()

        if self.config.mode == "openai":
            try:
                result = self._classify_openai(content)
                return self._apply_verdict(result)
            except Exception as exc:  # pragma: no cover - exercised in integration
                return self._fallback_result(error=str(exc), latency_ms=_latency_ms(start))

        result = self._classify_heuristic(content)
        result.latency_ms = _latency_ms(start)
        return self._apply_verdict(result)

    def _classify_heuristic(self, content: str) -> GuardrailResult:
        lowered = content.lower()
        counter = Counter()

        counter["prompt_injection"] = _count_patterns(lowered, _PROMPT_INJECTION_PATTERNS)
        counter["jailbreak"] = _count_patterns(lowered, _JAILBREAK_PATTERNS)
        counter["harmful_content"] = _count_patterns(lowered, _HARMFUL_PATTERNS)
        counter["pii_exposure"] = _count_patterns(lowered, _PII_PATTERNS)

        categories = {
            "prompt_injection": clip(counter["prompt_injection"] * 0.35),
            "jailbreak": clip(counter["jailbreak"] * 0.4),
            "harmful_content": clip(counter["harmful_content"] * 0.35),
            "pii_exposure": clip(counter["pii_exposure"] * 0.4),
        }
        categories["safe"] = clip(1.0 - max(categories.values(), default=0.0))

        return GuardrailResult(
            mode="heuristic",
            model="heuristic-rules",
            categories=categories,
            verdict="pass",
            latency_ms=0,
        )

    def _classify_openai(self, content: str) -> GuardrailResult:
        client = OpenAICompatClient(
            endpoint=self.config.endpoint or "",
            api_key=self.config.api_key,
            timeout_seconds=self.config.timeout_seconds,
        )
        result = client.classify_json(
            model=self.config.model,
            system_prompt=_GUARDRAIL_SYSTEM_PROMPT,
            user_prompt=content,
            temperature=0.0,
        )

        payload = result.payload
        categories = {
            "prompt_injection": clip(float(payload.get("prompt_injection", 0.0))),
            "jailbreak": clip(float(payload.get("jailbreak", 0.0))),
            "harmful_content": clip(float(payload.get("harmful_content", 0.0))),
            "pii_exposure": clip(float(payload.get("pii_exposure", 0.0))),
            "safe": clip(float(payload.get("safe", 0.0))),
        }

        return GuardrailResult(
            mode="openai",
            model=self.config.model,
            categories=categories,
            verdict="pass",
            latency_ms=result.latency_ms,
        )

    def _apply_verdict(self, result: GuardrailResult) -> GuardrailResult:
        max_risk = max(
            result.categories.get("prompt_injection", 0.0),
            result.categories.get("jailbreak", 0.0),
            result.categories.get("harmful_content", 0.0),
            result.categories.get("pii_exposure", 0.0),
        )

        if max_risk >= self.config.block_threshold:
            result.verdict = "block"
        elif max_risk >= self.config.flag_threshold:
            result.verdict = "flag"
        else:
            result.verdict = "pass"
        return result

    def _fallback_result(self, error: str, latency_ms: int) -> GuardrailResult:
        fallback = self.config.fallback_on_error

        if fallback == "pass":
            verdict = "pass"
            categories = {"prompt_injection": 0.0, "jailbreak": 0.0, "harmful_content": 0.0, "pii_exposure": 0.0, "safe": 1.0}
        elif fallback == "flag":
            verdict = "flag"
            categories = {"prompt_injection": 0.75, "jailbreak": 0.0, "harmful_content": 0.0, "pii_exposure": 0.0, "safe": 0.25}
        else:
            verdict = "block"
            categories = {"prompt_injection": 1.0, "jailbreak": 0.0, "harmful_content": 0.0, "pii_exposure": 0.0, "safe": 0.0}

        return GuardrailResult(
            mode=self.config.mode,
            model=self.config.model,
            categories=categories,
            verdict=verdict,
            latency_ms=latency_ms,
            error=error,
        )


def _count_patterns(text: str, patterns: list[str]) -> int:
    total = 0
    for pattern in patterns:
        total += len(re.findall(pattern, text))
    return total


def _latency_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
