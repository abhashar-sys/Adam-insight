from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from graph import build_graph
from nodes.customer_context_node import customer_context_node


class InvokeRequest(BaseModel):
    network: str = Field(..., description="Target network CIDR")
    locations: list[str] = Field(default_factory=list, description="Requested locations")


class MitigationFunctionOutputModel(BaseModel):
    function: str | None = None
    config: dict | None = None


class MitigationLocationOutputModel(BaseModel):
    location: str
    isSuppressed: bool
    functions: list[MitigationFunctionOutputModel]


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
    customer: str | None = None
    account_id: str | None = None
    account_name: str | None = None
    matched_cidr: str | None = None


class CustomersOutputModel(BaseModel):
    error: str | None = None
    matches: list[CustomerMatchModel] = Field(default_factory=list)


class ChakraRsErrorsOutputModel(BaseModel):
    active_attacks_error: str | None = None
    attack_events_error: str | None = None


class RecurrenceOutputModel(BaseModel):
    total_attacks: int
    average_gap_days: float | None = None
    longest_quiet_period_days: float | None = None
    shortest_gap_days: float | None = None


class DominantVectorOutputModel(BaseModel):
    vector: str
    occurrences: int
    share_percent: float


class VectorsOutputModel(BaseModel):
    dominant_vectors: list[DominantVectorOutputModel] = Field(default_factory=list)
    vector_diversity: int


class MagnitudeOutputModel(BaseModel):
    max_peak_bps: int | None = None
    average_peak_bps: float | None = None
    max_peak_pps: int | None = None
    largest_attack_recent: bool | None = None


class MitigationEffectivenessOutputModel(BaseModel):
    success_rate_percent: float | None = None
    successful_count: int
    failed_count: int
    unknown_outcome_count: int
    recurring_unmitigated_vectors: list[str] = Field(default_factory=list)


class DurationOutputModel(BaseModel):
    average_duration_hours: float | None = None
    longest_duration_hours: float | None = None
    ongoing_count: int


class HistoricalPatternOutputModel(BaseModel):
    summary: str
    recurrence: RecurrenceOutputModel | None = None
    vectors: VectorsOutputModel | None = None
    magnitude: MagnitudeOutputModel | None = None
    mitigation_effectiveness: MitigationEffectivenessOutputModel | None = None
    duration: DurationOutputModel | None = None


class AttackEventOutputModel(BaseModel):
    event_id: int
    attack_id: int
    start_time: str
    end_time: str | None = None
    attack_vectors: list[str] = Field(default_factory=list)
    agr_peak_bps: int | None = None
    agr_peak_pps: int | None = None
    is_active_attack: bool
    mitigation_successful: bool | None = None
    non_mitigated_vectors: list[str | None] = Field(default_factory=list)


class AttackReportSuccessOutputModel(BaseModel):
    customer_name: str
    kept_events: list[AttackEventOutputModel] = Field(default_factory=list)
    has_recent_attacks: bool
    message: str | None = None
    historical_pattern: HistoricalPatternOutputModel
    chakra_rs_failure: bool
    chakra_rs_errors: ChakraRsErrorsOutputModel


class AttackReportFailureOutputModel(BaseModel):
    customer_id: int | None = None
    customer_name: str | None = None
    chakra_rs_failure: Literal[True]
    chakra_rs_error: str


class CustomerContextOutputModel(BaseModel):
    mitigation: MitigationSuccessOutputModel | MitigationErrorOutputModel | None = None
    customers: CustomersOutputModel
    attack_reports: list[AttackReportSuccessOutputModel | AttackReportFailureOutputModel] = Field(default_factory=list)


class CustomerContextNodeResponse(BaseModel):
    customer_context: CustomerContextOutputModel | None


class GraphInvokeResponse(BaseModel):
    network: str
    locations: list[str]
    customer_context: CustomerContextOutputModel | None


app = FastAPI(
    title="Customer Context Agent API",
    version="0.1.0",
    description="HTTP facade for node services and LangGraph execution",
)

# Compile once and reuse across requests.
graph = build_graph()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/nodes/customer-context", response_model=CustomerContextNodeResponse)
def invoke_customer_context_node(payload: InvokeRequest) -> CustomerContextNodeResponse:
    state = {"network": payload.network, "locations": payload.locations, "customer_context": None}
    try:
        result = customer_context_node(state)
    except Exception as exc:  # pragma: no cover - defensive wrapper
        raise HTTPException(status_code=500, detail=f"customer_context node failed: {exc}") from exc
    return CustomerContextNodeResponse(customer_context=result.get("customer_context"))


@app.post("/graph/invoke", response_model=GraphInvokeResponse)
def invoke_graph(payload: InvokeRequest) -> GraphInvokeResponse:
    try:
        result = graph.invoke({"network": payload.network, "locations": payload.locations})
    except Exception as exc:  # pragma: no cover - defensive wrapper
        raise HTTPException(status_code=500, detail=f"graph invocation failed: {exc}") from exc

    return GraphInvokeResponse(
        network=result.get("network", payload.network),
        locations=result.get("locations", payload.locations),
        customer_context=result.get("customer_context"),
    )
