from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class TrustLevel(str, Enum):
    UNTRUSTED = "untrusted"
    SEMI_TRUSTED = "semi-trusted"
    TRUSTED = "trusted"


class SanitizerConfig(BaseModel):
    enabled: bool = True
    max_length: int = 50_000
    strip_invisible: bool = True
    strip_binary: bool = True
    strip_html_comments: bool = True
    normalize_unicode: bool = True
    collapse_whitespace: bool = True
    max_base64_blob_size: int = 256
    preserve_markdown: bool = True


class GuardrailConfig(BaseModel):
    enabled: bool = True
    mode: Literal["heuristic", "openai"] = "heuristic"
    model: str = "qwenguard-7b"
    endpoint: str | None = None
    api_key: str | None = None
    block_threshold: float = 0.9
    flag_threshold: float = 0.7
    fallback_on_error: Literal["quarantine", "pass", "flag"] = "quarantine"
    timeout_seconds: float = 10.0


class ScannerConfig(BaseModel):
    enabled: bool = True
    mode: Literal["heuristic", "openai"] = "heuristic"
    model: str = "gpt-4o-mini"
    endpoint: str | None = None
    api_key: str | None = None
    window_size: int = 250
    window_overlap: int = 50
    confidence_threshold: float = 0.7
    quarantine_threshold: float = 0.9
    max_concurrent_windows: int = 20
    fallback_on_error: Literal["quarantine", "pass", "flag"] = "quarantine"
    timeout_seconds: float = 10.0


class RuntimeConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    data_root: str = "./var/lib/untrusted-content"
    write_files: bool = True
    default_trust_level: TrustLevel = TrustLevel.UNTRUSTED
    return_content_on_quarantine: bool = False

    sanitizer: SanitizerConfig = Field(default_factory=SanitizerConfig)
    guardrail: GuardrailConfig = Field(default_factory=GuardrailConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)


class ContentInput(BaseModel):
    content: str
    source: str = "unknown"
    url: str | None = None
    content_type: str | None = None
    content_id: str | None = None


class PipelineOptions(BaseModel):
    trust_level: TrustLevel | None = None
    sanitize: bool | None = None
    guardrail: bool | None = None
    scan: bool | None = None
    window_size: int | None = None
    window_overlap: int | None = None


class PipelineRequest(BaseModel):
    input: ContentInput
    pipeline: PipelineOptions = Field(default_factory=PipelineOptions)


class SanitizerResult(BaseModel):
    content: str
    actions: list[str] = Field(default_factory=list)
    truncated: bool = False


class GuardrailResult(BaseModel):
    mode: str
    model: str
    categories: dict[str, float] = Field(default_factory=dict)
    verdict: Literal["pass", "flag", "block"]
    latency_ms: int
    error: str | None = None


class TextWindow(BaseModel):
    index: int
    start: int
    end: int
    content: str


class WindowFinding(BaseModel):
    window_index: int
    start: int
    end: int
    confidence: float
    pattern: str | None = None
    fragment: str


class ScannerResult(BaseModel):
    windows_scanned: int
    flagged_windows: list[WindowFinding] = Field(default_factory=list)
    max_confidence: float = 0.0
    quarantined: bool = False
    scan_time_ms: int = 0


class ThreatSignal(BaseModel):
    stage: str
    severity: Literal["info", "warn", "critical"]
    message: str
    confidence: float | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class PipelineMetadata(BaseModel):
    original_length: int
    sanitized_length: int
    truncated: bool
    sanitizer_actions: list[str] = Field(default_factory=list)
    guardrail: GuardrailResult | None = None
    windows_scanned: int = 0
    flagged_windows: list[WindowFinding] = Field(default_factory=list)
    scan_time_ms: int = 0
    pipeline_version: str = "0.1.0"
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    storage: dict[str, str | None] = Field(default_factory=dict)


class PipelineResponse(BaseModel):
    id: str
    clean: bool
    quarantined: bool
    content: str | None
    threats: list[ThreatSignal] = Field(default_factory=list)
    metadata: PipelineMetadata


class HoneypotTriggerRequest(BaseModel):
    tool_name: str
    session_key: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    incident_id: str | None = None


class HoneypotTriggerResponse(BaseModel):
    ok: bool
    incident_path: str | None = None
