from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from . import __version__
from .models import HoneypotTriggerRequest, HoneypotTriggerResponse, PipelineRequest, PipelineResponse
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


@app.post("/v1/honeypot/trigger", response_model=HoneypotTriggerResponse)
def honeypot_trigger(request: HoneypotTriggerRequest) -> HoneypotTriggerResponse:
    incident_path = pipeline.record_honeypot_trigger(request)
    return HoneypotTriggerResponse(ok=True, incident_path=incident_path)


@app.exception_handler(ValueError)
def value_error_handler(_, exc: ValueError) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": str(exc)})
