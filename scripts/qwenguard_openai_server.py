#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
import time
import uuid
from typing import Any

import torch
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from transformers import AutoProcessor, Qwen2_5_VLForConditionalGeneration

MODEL_ID = os.getenv("QWENGUARD_MODEL_ID", "AIML-TUDA/QwenGuard-v1.2-3B")
HOST = os.getenv("QWENGUARD_HOST", "127.0.0.1")
PORT = int(os.getenv("QWENGUARD_PORT", "8080"))
MAX_NEW_TOKENS = int(os.getenv("QWENGUARD_MAX_NEW_TOKENS", "96"))

_TOOL_NAME_RE = re.compile(r"\b(run_command|write_file|send_http_request|read_system_file)\b")
_TOOL_INTENT_RE = re.compile(
    r"\b(call|use|invoke|execute|run)\s+(the\s+)?(tool\s+)?(run_command|write_file|send_http_request|read_system_file)\b"
)


class ChatMessage(BaseModel):
    role: str
    content: str | list[dict[str, Any]]


class ChatCompletionsRequest(BaseModel):
    model: str = "qwenguard-3b"
    messages: list[ChatMessage]
    temperature: float | None = 0.0
    response_format: dict[str, Any] | None = None


app = FastAPI(title="qwenguard-openai-shim", version="0.1.0")
_state: dict[str, Any] = {}


@app.on_event("startup")
def startup() -> None:
    t0 = time.monotonic()
    processor = AutoProcessor.from_pretrained(MODEL_ID)
    model = Qwen2_5_VLForConditionalGeneration.from_pretrained(
        MODEL_ID,
        device_map="auto",
        torch_dtype="auto",
        low_cpu_mem_usage=True,
    )
    _state["processor"] = processor
    _state["model"] = model
    _state["loaded_ms"] = int((time.monotonic() - t0) * 1000)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model_id": MODEL_ID,
        "loaded_ms": _state.get("loaded_ms"),
    }


@app.post("/v1/chat/completions")
def chat_completions(request: ChatCompletionsRequest) -> dict[str, Any]:
    if "model" not in _state or "processor" not in _state:
        raise HTTPException(status_code=503, detail="Model not loaded")

    processor = _state["processor"]
    model = _state["model"]

    system_text = _flatten_content(next((m.content for m in request.messages if m.role == "system"), ""))
    user_text = _flatten_content(next((m.content for m in reversed(request.messages) if m.role == "user"), ""))

    prompt_messages = [
        {
            "role": "system",
            "content": [
                {
                    "type": "text",
                    "text": (
                        "You are a strict security classifier for untrusted text. "
                        "Return only valid JSON with keys: "
                        "prompt_injection, jailbreak, harmful_content, pii_exposure, safe. "
                        "Values must be floats between 0 and 1."
                        f"\n\nCaller instructions:\n{system_text}"
                    ),
                }
            ],
        },
        {
            "role": "user",
            "content": [
                {
                    "type": "text",
                    "text": f"Classify this text:\n{user_text}",
                }
            ],
        },
    ]

    prompt = processor.apply_chat_template(prompt_messages, tokenize=False, add_generation_prompt=True)
    inputs = processor(text=[prompt], padding=True, return_tensors="pt").to(model.device)

    t0 = time.monotonic()
    with torch.no_grad():
        out = model.generate(**inputs, max_new_tokens=MAX_NEW_TOKENS, do_sample=False)
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    generated = [o[len(i) :] for i, o in zip(inputs.input_ids, out)]
    text = processor.batch_decode(generated, skip_special_tokens=True, clean_up_tokenization_spaces=False)[0]

    scores = _extract_scores(model_output=text, source_text=user_text)
    content = json.dumps(scores)

    return {
        "id": f"chatcmpl-{uuid.uuid4()}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": request.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": int(inputs.input_ids.shape[-1]),
            "completion_tokens": int(generated[0].shape[-1]) if generated else 0,
            "total_tokens": int(inputs.input_ids.shape[-1] + (generated[0].shape[-1] if generated else 0)),
            "latency_ms": elapsed_ms,
        },
    }


def _flatten_content(content: str | list[dict[str, Any]]) -> str:
    if isinstance(content, str):
        return content
    chunks: list[str] = []
    for item in content:
        if isinstance(item, dict) and item.get("type") == "text":
            chunks.append(str(item.get("text", "")))
    return "\n".join(chunks)


def _extract_scores(*, model_output: str, source_text: str) -> dict[str, float]:
    text = model_output.strip()

    parsed = _try_parse_json_object(text)
    required_keys = {"prompt_injection", "jailbreak", "harmful_content", "pii_exposure", "safe"}
    if parsed and required_keys.issubset(parsed.keys()):
        return {
            "prompt_injection": _clamp(parsed.get("prompt_injection", 0.0)),
            "jailbreak": _clamp(parsed.get("jailbreak", 0.0)),
            "harmful_content": _clamp(parsed.get("harmful_content", 0.0)),
            "pii_exposure": _clamp(parsed.get("pii_exposure", 0.0)),
            "safe": _clamp(parsed.get("safe", 0.0)),
        }

    lower = source_text.lower()
    prompt_injection = 0.0
    jailbreak = 0.0
    harmful = 0.0
    pii = 0.0

    if any(k in lower for k in ["ignore previous", "disregard previous", "override instructions", "you are now", "system:"]):
        prompt_injection = 0.85
    elif _TOOL_INTENT_RE.search(lower):
        prompt_injection = 0.8
    elif _TOOL_NAME_RE.search(lower) and any(k in lower for k in ["credentials", "private key", "curl", "exfiltrate"]):
        prompt_injection = 0.65

    if any(k in lower for k in ["jailbreak", "dan", "bypass safety"]):
        jailbreak = 0.8
    if any(k in lower for k in ["curl", "exfiltrate", "malicious", "harmful"]):
        harmful = 0.7
    if any(k in lower for k in ["api key", "private key", "credentials", "ssn", "pii"]):
        pii = 0.7

    if max(prompt_injection, jailbreak, harmful, pii) == 0.0 and "safe" in lower:
        safe = 0.95
    else:
        safe = max(0.0, 1.0 - max(prompt_injection, jailbreak, harmful, pii))

    return {
        "prompt_injection": prompt_injection,
        "jailbreak": jailbreak,
        "harmful_content": harmful,
        "pii_exposure": pii,
        "safe": safe,
    }


def _try_parse_json_object(text: str) -> dict[str, Any] | None:
    try:
        value = json.loads(text)
        if isinstance(value, dict):
            return value
    except Exception:
        pass

    match = re.search(r"\{.*\}", text, flags=re.DOTALL)
    if not match:
        return None

    try:
        value = json.loads(match.group(0))
        if isinstance(value, dict):
            return value
    except Exception:
        return None
    return None


def _clamp(value: Any) -> float:
    try:
        f = float(value)
    except Exception:
        return 0.0
    return max(0.0, min(1.0, f))


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)
