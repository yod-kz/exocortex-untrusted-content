from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from typing import Any

from . import __version__
from .guardrail import GuardrailEngine
from .models import (
    GuardrailConfig,
    HoneypotTriggerRequest,
    PipelineMetadata,
    PipelineRequest,
    PipelineResponse,
    RuntimeConfig,
    SanitizerConfig,
    ScannerConfig,
    ThreatSignal,
    TrustLevel,
)
from .sanitizer import Sanitizer
from .scanner import ScannerEngine, summarize_findings
from .storage import StorageManager
from .utils import env_bool, env_float, env_int


class UntrustedContentPipeline:
    def __init__(self, config: RuntimeConfig | None = None):
        self.config = config or load_runtime_config_from_env()
        self.storage = StorageManager(self.config)

        self._sanitizer = Sanitizer(self.config.sanitizer)
        self._guardrail = GuardrailEngine(self.config.guardrail)
        self._scanner = ScannerEngine(self.config.scanner)

    def process(self, request: PipelineRequest) -> PipelineResponse:
        content_id = request.input.content_id or str(uuid.uuid4())

        raw_path = self.storage.store_raw(content_id, request.input)

        stage_plan = _resolve_stage_plan(
            trust_level=request.pipeline.trust_level or self.config.default_trust_level,
            sanitize_override=request.pipeline.sanitize,
            guardrail_override=request.pipeline.guardrail,
            scan_override=request.pipeline.scan,
        )

        text = request.input.content
        sanitizer_actions: list[str] = []
        truncated = False
        threats: list[ThreatSignal] = []

        if stage_plan["sanitize"] and self.config.sanitizer.enabled:
            sanitized = self._sanitizer.sanitize(text)
            text = sanitized.content
            sanitizer_actions = sanitized.actions
            truncated = sanitized.truncated

        guardrail_result = None
        quarantined = False

        if stage_plan["guardrail"] and self.config.guardrail.enabled:
            guardrail_result = self._guardrail.classify(text)
            if guardrail_result.verdict == "block":
                quarantined = True
                threats.append(
                    ThreatSignal(
                        stage="guardrail",
                        severity="critical",
                        message="Guardrail classifier blocked the content",
                        confidence=max(
                            guardrail_result.categories.get("prompt_injection", 0.0),
                            guardrail_result.categories.get("jailbreak", 0.0),
                            guardrail_result.categories.get("harmful_content", 0.0),
                            guardrail_result.categories.get("pii_exposure", 0.0),
                        ),
                        details={"categories": guardrail_result.categories, "error": guardrail_result.error},
                    )
                )
            elif guardrail_result.verdict == "flag":
                threats.append(
                    ThreatSignal(
                        stage="guardrail",
                        severity="warn",
                        message="Guardrail classifier flagged suspicious content",
                        confidence=max(
                            guardrail_result.categories.get("prompt_injection", 0.0),
                            guardrail_result.categories.get("jailbreak", 0.0),
                            guardrail_result.categories.get("harmful_content", 0.0),
                            guardrail_result.categories.get("pii_exposure", 0.0),
                        ),
                        details={"categories": guardrail_result.categories, "error": guardrail_result.error},
                    )
                )

        scanner = self._scanner.with_overrides(
            window_size=request.pipeline.window_size,
            window_overlap=request.pipeline.window_overlap,
        )

        scan_result = scanner.scan(text) if stage_plan["scan"] and self.config.scanner.enabled and not quarantined else None

        if scan_result:
            if scan_result.flagged_windows:
                severity = "critical" if scan_result.quarantined else "warn"
                threats.append(
                    ThreatSignal(
                        stage="scanner",
                        severity=severity,
                        message="Windowed scanner identified injection signatures",
                        confidence=scan_result.max_confidence,
                        details={"findings": summarize_findings(scan_result.flagged_windows)},
                    )
                )

            if scan_result.quarantined:
                quarantined = True

        clean = not quarantined
        output_content = text if clean or self.config.return_content_on_quarantine else None

        metadata = PipelineMetadata(
            original_length=len(request.input.content),
            sanitized_length=len(text),
            truncated=truncated,
            sanitizer_actions=sanitizer_actions,
            guardrail=guardrail_result,
            windows_scanned=scan_result.windows_scanned if scan_result else 0,
            flagged_windows=scan_result.flagged_windows if scan_result else [],
            scan_time_ms=scan_result.scan_time_ms if scan_result else 0,
            pipeline_version=__version__,
            trust_level=request.pipeline.trust_level or self.config.default_trust_level,
            storage={
                "raw": raw_path,
                "clean": None,
                "incident": None,
            },
        )

        clean_record = {
            "id": content_id,
            "timestamp": _timestamp(),
            "source": request.input.source,
            "source_url": request.input.url,
            "content": output_content,
            "clean": clean,
            "quarantined": quarantined,
            "threats": [threat.model_dump(mode="json") for threat in threats],
            "metadata": metadata.model_dump(mode="json"),
            "provenance": f"{metadata.trust_level.value}:{request.input.source}",
            "pipeline_version": __version__,
        }
        clean_path = self.storage.store_clean(content_id, clean_record)
        metadata.storage["clean"] = clean_path

        incident_path = None
        if quarantined:
            incident_id = f"quarantine-{content_id}"
            incident_record = {
                "id": incident_id,
                "timestamp": _timestamp(),
                "type": "quarantine",
                "content_id": content_id,
                "source": request.input.source,
                "url": request.input.url,
                "threats": [threat.model_dump(mode="json") for threat in threats],
                "metadata": metadata.model_dump(mode="json"),
            }
            incident_path = self.storage.store_incident(incident_id, incident_record)
            metadata.storage["incident"] = incident_path

        return PipelineResponse(
            id=content_id,
            clean=clean,
            quarantined=quarantined,
            content=output_content,
            threats=threats,
            metadata=metadata,
        )

    def record_honeypot_trigger(self, request: HoneypotTriggerRequest) -> str | None:
        incident_id = request.incident_id or f"honeypot-{uuid.uuid4()}"
        incident_record = {
            "id": incident_id,
            "timestamp": _timestamp(),
            "type": "honeypot",
            "tool_name": request.tool_name,
            "session_key": request.session_key,
            "arguments": request.arguments,
        }
        return self.storage.store_incident(incident_id, incident_record)


def load_runtime_config_from_env() -> RuntimeConfig:
    guardrail_cfg = GuardrailConfig(
        enabled=env_bool("UTC_GUARDRAIL_ENABLED", True),
        mode=os.getenv("UTC_GUARDRAIL_MODE", "heuristic"),
        model=os.getenv("UTC_GUARDRAIL_MODEL", "qwenguard-7b"),
        endpoint=os.getenv("UTC_GUARDRAIL_ENDPOINT"),
        api_key=os.getenv("UTC_GUARDRAIL_API_KEY"),
        block_threshold=env_float("UTC_GUARDRAIL_BLOCK_THRESHOLD", 0.9),
        flag_threshold=env_float("UTC_GUARDRAIL_FLAG_THRESHOLD", 0.7),
        fallback_on_error=os.getenv("UTC_GUARDRAIL_FALLBACK", "quarantine"),
        timeout_seconds=env_float("UTC_GUARDRAIL_TIMEOUT", 10.0),
    )

    scanner_cfg = ScannerConfig(
        enabled=env_bool("UTC_SCANNER_ENABLED", True),
        mode=os.getenv("UTC_SCANNER_MODE", "heuristic"),
        model=os.getenv("UTC_SCANNER_MODEL", "gpt-4o-mini"),
        endpoint=os.getenv("UTC_SCANNER_ENDPOINT"),
        api_key=os.getenv("UTC_SCANNER_API_KEY"),
        window_size=env_int("UTC_SCANNER_WINDOW_SIZE", 250),
        window_overlap=env_int("UTC_SCANNER_WINDOW_OVERLAP", 50),
        confidence_threshold=env_float("UTC_SCANNER_FLAG_THRESHOLD", 0.7),
        quarantine_threshold=env_float("UTC_SCANNER_QUARANTINE_THRESHOLD", 0.9),
        max_concurrent_windows=env_int("UTC_SCANNER_MAX_CONCURRENCY", 20),
        fallback_on_error=os.getenv("UTC_SCANNER_FALLBACK", "quarantine"),
        timeout_seconds=env_float("UTC_SCANNER_TIMEOUT", 10.0),
    )

    sanitizer_cfg = SanitizerConfig(
        enabled=env_bool("UTC_SANITIZER_ENABLED", True),
        max_length=env_int("UTC_SANITIZER_MAX_LENGTH", 50_000),
        strip_invisible=env_bool("UTC_SANITIZER_STRIP_INVISIBLE", True),
        strip_binary=env_bool("UTC_SANITIZER_STRIP_BINARY", True),
        strip_html_comments=env_bool("UTC_SANITIZER_STRIP_HTML_COMMENTS", True),
        normalize_unicode=env_bool("UTC_SANITIZER_NORMALIZE_UNICODE", True),
        collapse_whitespace=env_bool("UTC_SANITIZER_COLLAPSE_WHITESPACE", True),
        max_base64_blob_size=env_int("UTC_SANITIZER_MAX_BASE64_BLOB", 256),
        preserve_markdown=env_bool("UTC_SANITIZER_PRESERVE_MARKDOWN", True),
    )

    trust_level_raw = os.getenv("UTC_DEFAULT_TRUST_LEVEL", TrustLevel.UNTRUSTED.value)

    return RuntimeConfig(
        data_root=os.getenv("UTC_DATA_ROOT", "./var/lib/untrusted-content"),
        write_files=env_bool("UTC_WRITE_FILES", True),
        default_trust_level=TrustLevel(trust_level_raw),
        return_content_on_quarantine=env_bool("UTC_RETURN_CONTENT_ON_QUARANTINE", False),
        sanitizer=sanitizer_cfg,
        guardrail=guardrail_cfg,
        scanner=scanner_cfg,
    )


def _resolve_stage_plan(
    *,
    trust_level: TrustLevel,
    sanitize_override: bool | None,
    guardrail_override: bool | None,
    scan_override: bool | None,
) -> dict[str, bool]:
    defaults = {
        TrustLevel.UNTRUSTED: {"sanitize": True, "guardrail": True, "scan": True},
        TrustLevel.SEMI_TRUSTED: {"sanitize": True, "guardrail": True, "scan": False},
        TrustLevel.TRUSTED: {"sanitize": True, "guardrail": False, "scan": False},
    }[trust_level].copy()

    if sanitize_override is not None:
        defaults["sanitize"] = sanitize_override
    if guardrail_override is not None:
        defaults["guardrail"] = guardrail_override
    if scan_override is not None:
        defaults["scan"] = scan_override

    return defaults


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
