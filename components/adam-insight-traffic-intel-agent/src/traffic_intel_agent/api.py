"""FastAPI application for the Adam Insight traffic analysis agent.

Exposes two HTTP endpoints:

    GET  /health   — liveness / readiness probe
    POST /analyze  — run the full LangGraph pipeline and return a
                     TrafficSnapshot as JSON

The LangGraph graph is compiled once at import time (module-level singleton)
and reused across requests.  The blocking ``graph.invoke()`` call is offloaded
to a ``ThreadPoolExecutor`` so the async event loop is never stalled.

Starting the server
-------------------
    # via CLI entry-point (after pip install):
    traffic-intel-api

    # or directly with uvicorn (useful for --reload during development):
    uvicorn traffic_intel_agent.api:app --reload --port 8000

Interactive docs
----------------
    http://localhost:8000/docs      # Swagger UI
    http://localhost:8000/redoc     # ReDoc
"""

from __future__ import annotations

import asyncio
import logging
import os
from concurrent.futures import ThreadPoolExecutor
from typing import List

import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from traffic_intel_agent.models.traffic_analysis import TrafficSnapshot

logger = logging.getLogger(__name__)

# ─── Compile the graph once at startup ────────────────────────────────────────
# Imported lazily inside the lifespan handler so that connection errors surface
# at startup (not at import time), making container health checks reliable.

_graph = None  # populated during startup


# ─── FastAPI application ───────────────────────────────────────────────────────

app = FastAPI(
    title="Adam Insight — Traffic Intel Agent",
    description=(
        "REST API for the LangGraph-based sFlow DDoS traffic analysis pipeline. "
        "Submit a target IP (and optional scrub-center list) to receive a full "
        "TrafficSnapshot with baseline stats, peak windows, and per-peak breakdowns."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Shared thread-pool for blocking graph.invoke() calls
_executor = ThreadPoolExecutor(max_workers=int(os.getenv("API_WORKERS", "4")))


# ─── Lifespan: compile graph once ─────────────────────────────────────────────

@app.on_event("startup")
async def _startup() -> None:
    """Compile the LangGraph graph once and cache it."""
    global _graph
    # Import here so heavy dependencies load after the process is forked/warmed
    from traffic_intel_agent.graph.graph import graph  # noqa: PLC0415
    _graph = graph
    logger.info("LangGraph compiled and ready.")


# ─── Request / Response schemas ───────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    """Input for the /analyze endpoint."""

    target: str = Field(
        ...,
        description="IP address or CIDR block to analyse (e.g. '192.0.2.10').",
        examples=["192.0.2.10"],
    )
    scrub_centers: List[str] = Field(
        default_factory=list,
        description=(
            "Optional list of scrub-center names to restrict analysis to. "
            "Leave empty to include all scrub centers."
        ),
        examples=[["SC-LON", "SC-AMS"]],
    )


class HealthResponse(BaseModel):
    """Response model for the health endpoint."""

    status: str = "ok"


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health / liveness probe",
    tags=["ops"],
)
async def health() -> HealthResponse:
    """Return ``{"status": "ok"}`` — used by load balancers and container orchestrators."""
    return HealthResponse()


@app.post(
    "/analyze",
    response_model=TrafficSnapshot,
    summary="Run traffic analysis pipeline",
    tags=["analysis"],
    responses={
        200: {"description": "TrafficSnapshot with baseline, peaks, and breakdowns."},
        422: {"description": "Validation error — bad request body."},
        500: {"description": "Internal pipeline error."},
    },
)
async def analyze(request: AnalyzeRequest) -> TrafficSnapshot:
    """Run the full LangGraph traffic analysis pipeline.

    Executes the following steps (in parallel where possible):
    - Resolve scrub centers → device IPs
    - Fetch 6-day pooled baseline from Cassandra
    - Detect top-5 BPS / PPS peaks from ClickHouse (overall + per-SC)
    - Decompose each peak (protocol, port, ethernet-type, SC shares)
    - Compute deltas vs baseline
    - Assemble a ``TrafficSnapshot``

    The pipeline runs in a background thread so the async event loop
    is never blocked.
    """
    if _graph is None:
        raise HTTPException(status_code=503, detail="Graph not yet initialised — retry shortly.")

    loop = asyncio.get_event_loop()

    def _run() -> TrafficSnapshot:
        result = _graph.invoke(
            {
                "detection_target": request.target,
                "scrub_centers": request.scrub_centers,
            }
        )
        snapshot: TrafficSnapshot | None = result.get("output")
        if snapshot is None:
            raise ValueError("Pipeline produced no output.")
        return snapshot

    try:
        timeout = float(os.getenv("ANALYZE_TIMEOUT_SECONDS", "120"))
        snapshot = await asyncio.wait_for(
            loop.run_in_executor(_executor, _run),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        logger.error("Pipeline timed out after %.0fs for target=%s", timeout, request.target)
        raise HTTPException(
            status_code=504,
            detail=f"Analysis timed out after {timeout:.0f}s. Try again or narrow the scope.",
        )
    except ValueError as exc:
        logger.warning("Pipeline returned no output for target=%s: %s", request.target, exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Pipeline error for target=%s", request.target)
        raise HTTPException(
            status_code=500,
            detail=f"Pipeline error: {exc}",
        ) from exc

    return snapshot


# ─── Entry-point for `traffic-intel-api` CLI script ───────────────────────────

def run() -> None:
    """Start the Uvicorn server.  Called by the ``traffic-intel-api`` console script."""
    host = os.getenv("API_HOST", "0.0.0.0")  # noqa: S104
    port = int(os.getenv("API_PORT", "8080"))   # must match Dockerfile EXPOSE + Helm targetPort
    log_level = os.getenv("API_LOG_LEVEL", "info")

    uvicorn.run(
        "traffic_intel_agent.api:app",
        host=host,
        port=port,
        log_level=log_level,
        # workers > 1 only works without reload; set via API_SERVER_WORKERS env var
        workers=int(os.getenv("API_SERVER_WORKERS", "1")),
    )


if __name__ == "__main__":
    run()
