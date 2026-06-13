from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from . import __version__
from .models import (
    HoneypotTriggerRequest,
    HoneypotTriggerResponse,
    PipelineRequest,
    PipelineResponse,
    QuarantineRawResponse,
)
from .pipeline import UntrustedContentPipeline

app = FastAPI(
    title="tool-untrusted-content",
    version=__version__,
    description="Sanitize and scan untrusted content before agent ingestion.",
)

pipeline = UntrustedContentPipeline()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "version": __version__}


@app.post("/v1/pipeline", response_model=PipelineResponse)
def run_pipeline(request: PipelineRequest) -> PipelineResponse:
    return pipeline.process(request)


# Compatibility alias for clients that address pipelines by id, e.g. the
# OpenClaw untrusted-content guard plugin (POST /v1/pipelines/{id}/run). This
# service hosts a single default pipeline, so the id is accepted for protocol
# parity and the request runs through the same processing path.
@app.post("/v1/pipelines/{pipeline_id}/run", response_model=PipelineResponse)
def run_named_pipeline(pipeline_id: str, request: PipelineRequest) -> PipelineResponse:
    return pipeline.process(request)


# Operator-only raw retrieval. The stored raw content is hostile and is never
# returned to the agent; this route exists solely for explicit operator inspection
# of a quarantined item by its content id. read_raw enforces the path-traversal
# guard and returns None (-> 404) for unsafe or missing ids.
@app.get("/v1/quarantine/{content_id}", response_model=QuarantineRawResponse)
def get_quarantine_raw(content_id: str) -> QuarantineRawResponse:
    record = pipeline.storage.read_raw(content_id)
    if record is None:
        raise HTTPException(status_code=404, detail="not found")
    return QuarantineRawResponse(
        id=record.get("id", content_id),
        raw_content=record.get("raw_content", ""),
        source=record.get("source"),
        url=record.get("url"),
        content_type=record.get("content_type"),
        sha256=record.get("sha256"),
        timestamp=record.get("timestamp"),
    )


@app.post("/v1/honeypot/trigger", response_model=HoneypotTriggerResponse)
def honeypot_trigger(request: HoneypotTriggerRequest) -> HoneypotTriggerResponse:
    incident_path = pipeline.record_honeypot_trigger(request)
    return HoneypotTriggerResponse(ok=True, incident_path=incident_path)


@app.exception_handler(ValueError)
def value_error_handler(_, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})
