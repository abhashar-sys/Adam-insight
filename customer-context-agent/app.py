"""Customer Context Agent — FastAPI service.

Called by the orchestrator at:
    POST /nodes/customer-context

Input  matches  CustomerContextInput  in orchestrator-service/app.py.
Output wraps CustomerContextOutputModel in the standard UnifiedEnvelope.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Literal, Optional, Union,Generic,TypeVar

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from graph import build_graph
from nodes.customer_context_node import customer_context_node


# ── Agent-internal models (unchanged) ────────────────────────────────────────

class InvokeRequest(BaseModel):
    network: str = Field(..., description="Target network CIDR")
    locations: List[str] = Field(default_factory=list, description="Requested locations")


class MitigationFunctionOutputModel(BaseModel):
    function: Optional[str] = None
    config: Optional[dict] = None


class MitigationLocationOutputModel(BaseModel):
    location: str
    isSuppressed: bool
    functions: List[MitigationFunctionOutputModel]


class MitigationSuccessOutputModel(BaseModel):
    mitigated_network: str | None = None
    event_id: str | int | None = None
    event_customer: str | None = None
    mitigation_state: str | None = None
    is_auto_mitigation: bool | None = None
    locations: list[MitigationLocationOutputModel] = Field(default_factory=list)


class MitigationErrorOutputModel(BaseModel):
    error: str


class CustomerMatchModel(BaseModel):
    customer: Optional[str] = None
    account_id: Optional[str] = None
    account_name: Optional[str] = None
    matched_cidr: Optional[str] = None


class CustomersOutputModel(BaseModel):
    error: Optional[str] = None
    matches: List[CustomerMatchModel] = Field(default_factory=list)


class ChakraRsErrorsOutputModel(BaseModel):
    active_attacks_error: Optional[str] = None
    attack_events_error: Optional[str] = None


class RecurrenceOutputModel(BaseModel):
    total_attacks: int
    average_gap_days: Optional[float] = None
    longest_quiet_period_days: Optional[float] = None
    shortest_gap_days: Optional[float] = None


class DominantVectorOutputModel(BaseModel):
    vector: str
    occurrences: int
    share_percent: float


class VectorsOutputModel(BaseModel):
    dominant_vectors: List[DominantVectorOutputModel] = Field(default_factory=list)
    vector_diversity: int


class MagnitudeOutputModel(BaseModel):
    max_peak_bps: Optional[int] = None
    average_peak_bps: Optional[float] = None
    max_peak_pps: Optional[int] = None
    largest_attack_recent: Optional[bool] = None


class MitigationEffectivenessOutputModel(BaseModel):
    success_rate_percent: Optional[float] = None
    successful_count: int
    failed_count: int
    unknown_outcome_count: int
    recurring_unmitigated_vectors: List[str] = Field(default_factory=list)


class DurationOutputModel(BaseModel):
    average_duration_hours: Optional[float] = None
    longest_duration_hours: Optional[float] = None
    ongoing_count: int


class HistoricalPatternOutputModel(BaseModel):
    summary: str
    recurrence: Optional[RecurrenceOutputModel] = None
    vectors: Optional[VectorsOutputModel] = None
    magnitude: Optional[MagnitudeOutputModel] = None
    mitigation_effectiveness: Optional[MitigationEffectivenessOutputModel] = None
    duration: Optional[DurationOutputModel] = None


class AttackEventOutputModel(BaseModel):
    event_id: int
    attack_id: int
    start_time: str
    end_time: Optional[str] = None
    attack_vectors: List[str] = Field(default_factory=list)
    agr_peak_bps: Optional[int] = None
    agr_peak_pps: Optional[int] = None
    is_active_attack: bool
    mitigation_successful: Optional[bool] = None
    non_mitigated_vectors: List[Optional[str]] = Field(default_factory=list)


class AttackReportSuccessOutputModel(BaseModel):
    customer_name: str
    kept_events: List[AttackEventOutputModel] = Field(default_factory=list)
    has_recent_attacks: bool
    message: Optional[str] = None
    historical_pattern: HistoricalPatternOutputModel
    chakra_rs_failure: bool
    chakra_rs_errors: ChakraRsErrorsOutputModel


class AttackReportFailureOutputModel(BaseModel):
    customer_id: Optional[int] = None
    customer_name: Optional[str] = None
    chakra_rs_failure: Literal[True]
    chakra_rs_error: str


class CustomerContextOutputModel(BaseModel):
    mitigation: Optional[Union[MitigationSuccessOutputModel, MitigationErrorOutputModel]] = None
    customers: CustomersOutputModel
    attack_reports: List[Union[AttackReportSuccessOutputModel, AttackReportFailureOutputModel]] = Field(default_factory=list)


# ── Envelope Models ───────────────────────────────────────────────────────────
T=TypeVar("T")
class ErrorBlock(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class UnifiedEnvelope(BaseModel,Generic[T]):
    request_id: str
    service: str
    status: str                          # "success" | "partial" | "error"
    generated_at_ns: int
    latency_ms: int
    error: Optional[ErrorBlock] = None
    data: T

class NodeResponseData(BaseModel):
    customer_context: Optional[CustomerContextOutputModel] = None


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Customer Context Agent API",
    version="0.1.0",
    description="Provides customer context information for a given network CIDR and a list of scrub center locations, including mitigation status, customer matches, and attack reports.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Compile the graph once and reuse across requests.
graph = build_graph()


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", summary="Health check")
def health() -> Dict[str, str]:
    return {"status": "ok", "service": "customer-context"}


# ── Primary orchestrator endpoint ─────────────────────────────────────────────

@app.post(
    "/nodes/customer-context",
    response_model=UnifiedEnvelope[NodeResponseData],
    summary="Run customer context node (orchestrator contract)",
)
def invoke_customer_context_node(payload: InvokeRequest) -> UnifiedEnvelope:
    """Fetch mitigation, customer matches, and attack reports for a network CIDR.

    Called by the orchestrator with ``network`` and optional ``locations``.
    Returns the full CustomerContextOutputModel wrapped in UnifiedEnvelope.
    """
    request_id = str(uuid.uuid4())
    t_start = time.time()
    generated_at_ns = time.time_ns()

    state = {
        "network": payload.network,
        "locations": payload.locations,
        "customer_context": None,
    }

    try:
        result = customer_context_node(state)
        latency_ms = int((time.time() - t_start) * 1000)

        ctx = result.get("customer_context")

        # Determine status
        if ctx is None:
            status = "partial"
            data: Dict[str, Any] = {"customer_context": None}
        else:
            ctx_dict = ctx.model_dump() if hasattr(ctx, "model_dump") else ctx
            has_customers = bool(
                isinstance(ctx_dict.get("customers"), dict)
                and ctx_dict["customers"].get("matches")
            )
            status = "success" if has_customers else "partial"
            data = {"customer_context": ctx_dict}

        return UnifiedEnvelope(
            request_id=request_id,
            service="customer-context",
            status=status,
            generated_at_ns=generated_at_ns,
            latency_ms=latency_ms,
            data=data,
        )

    except Exception as exc:
        latency_ms = int((time.time() - t_start) * 1000)
        return UnifiedEnvelope(
            request_id=request_id,
            service="customer-context",
            status="error",
            generated_at_ns=generated_at_ns,
            latency_ms=latency_ms,
            error=ErrorBlock(
                code="NODE_FAILED",
                message=str(exc),
            ),
            data={},
        )


# ── Graph invoke (kept for direct testing) ────────────────────────────────────

@app.post(
    "/graph/invoke",
    response_model=UnifiedEnvelope,
    summary="Run full LangGraph pipeline",
)
def invoke_graph(payload: InvokeRequest) -> UnifiedEnvelope:
    """Run the full LangGraph pipeline and return all state fields."""
    request_id = str(uuid.uuid4())
    t_start = time.time()
    generated_at_ns = time.time_ns()

    try:
        result = graph.invoke({
            "network": payload.network,
            "locations": payload.locations,
        })
        latency_ms = int((time.time() - t_start) * 1000)

        ctx = result.get("customer_context")
        ctx_dict = ctx.model_dump() if hasattr(ctx, "model_dump") else ctx

        return UnifiedEnvelope(
            request_id=request_id,
            service="customer-context",
            status="success",
            generated_at_ns=generated_at_ns,
            latency_ms=latency_ms,
            data={
                "network": result.get("network", payload.network),
                "locations": result.get("locations", payload.locations),
                "customer_context": ctx_dict,
            },
        )

    except Exception as exc:
        latency_ms = int((time.time() - t_start) * 1000)
        return UnifiedEnvelope(
            request_id=request_id,
            service="customer-context",
            status="error",
            generated_at_ns=generated_at_ns,
            latency_ms=latency_ms,
            error=ErrorBlock(
                code="GRAPH_FAILED",
                message=str(exc),
            ),
            data={},
        )


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8013, reload=True)
