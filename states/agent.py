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
    event_version: Optional[int]
    event_customer: Optional[str]
    lifecycle_state: Optional[str]
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


class HistoricalPatternOutput(TypedDict):
    summary: str
    recurrence: Optional[dict]
    vectors: Optional[dict]
    magnitude: Optional[dict]
    mitigation_effectiveness: Optional[dict]
    duration: Optional[dict]


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
