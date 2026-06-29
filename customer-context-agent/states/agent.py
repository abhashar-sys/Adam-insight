from typing import TypedDict, Optional, TypeAlias


class MitigationFunctionOutput(TypedDict, total=False):
    function: str
    config: dict | None


class MitigationLocationOutput(TypedDict):
    location: str
    isSuppressed: bool
    functions: list[MitigationFunctionOutput]


class MitigationSuccessOutput(TypedDict):
    matched_cidr: Optional[str]
    event_id: Optional[str | int]
    event_customer: Optional[str]
    mitigation_state: Optional[str]
    account_id: Optional[str]
    account_name: Optional[str]
    is_auto_mitigation: Optional[bool]
    locations: list[MitigationLocationOutput]


class MitigationErrorOutput(TypedDict):
    error: str


MitigationOutput: TypeAlias = MitigationSuccessOutput | MitigationErrorOutput


class CustomerMatch(TypedDict):
    customer: Optional[str]
    account_id: Optional[str]
    account_name: Optional[str]
    matched_cidr: Optional[str]


class CustomersOutput(TypedDict):
    error: Optional[str]
    matches: list[CustomerMatch]


class ChakraRsErrorsOutput(TypedDict):
    active_attacks_error: Optional[str]
    attack_events_error: Optional[str]


class RecurrenceOutput(TypedDict):
    total_attacks: int
    average_gap_days: Optional[float]
    longest_quiet_period_days: Optional[float]
    shortest_gap_days: Optional[float]


class DominantVectorOutput(TypedDict):
    vector: str
    occurrences: int
    share_percent: float


class VectorsOutput(TypedDict):
    dominant_vectors: list[DominantVectorOutput]
    vector_diversity: int


class MagnitudeOutput(TypedDict):
    max_peak_bps: Optional[int]
    average_peak_bps: Optional[float]
    max_peak_pps: Optional[int]
    largest_attack_recent: Optional[bool]


class MitigationEffectivenessOutput(TypedDict):
    success_rate_percent: Optional[float]
    successful_count: int
    failed_count: int
    unknown_outcome_count: int
    recurring_unmitigated_vectors: list[str]


class DurationOutput(TypedDict):
    average_duration_hours: Optional[float]
    longest_duration_hours: Optional[float]
    ongoing_count: int


class HistoricalPatternOutput(TypedDict):
    summary: str
    recurrence: Optional[RecurrenceOutput]
    vectors: Optional[VectorsOutput]
    magnitude: Optional[MagnitudeOutput]
    mitigation_effectiveness: Optional[MitigationEffectivenessOutput]
    duration: Optional[DurationOutput]


class AttackEventOutput(TypedDict):
    event_id: int
    attack_id: int
    start_time: str
    end_time: Optional[str]
    attack_vectors: list[str]
    agr_peak_bps: Optional[int]
    agr_peak_pps: Optional[int]
    is_active_attack: bool
    mitigation_successful: Optional[bool]
    non_mitigated_vectors: list[Optional[str]]


class AttackReportSuccessOutput(TypedDict):
    customer_name: str
    kept_events: list[AttackEventOutput]
    has_recent_attacks: bool
    message: Optional[str]
    historical_pattern: HistoricalPatternOutput
    chakra_rs_failure: bool
    chakra_rs_errors: ChakraRsErrorsOutput


class AttackReportFailureOutput(TypedDict):
    customer_id: Optional[int]
    customer_name: Optional[str]
    chakra_rs_failure: bool
    chakra_rs_error: str


AttackReportOutput: TypeAlias = AttackReportSuccessOutput | AttackReportFailureOutput


class CustomerContextOutput(TypedDict):
    mitigation: Optional[MitigationOutput]
    customers: CustomersOutput
    attack_reports: list[AttackReportOutput]


class AgentState(TypedDict):
    network: str
    locations: list[str]
    customer_context: Optional[CustomerContextOutput]
