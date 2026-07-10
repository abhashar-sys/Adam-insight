from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class SharedInvocationInput(BaseModel):
    request_id: str | None = Field(default=None, description="Optional request correlation ID")
    network: str = Field(..., description="Target network CIDR or IP")
    locations: list[str] = Field(default_factory=list, description="Requested locations")
    start_epoch: int | None = Field(default=None, description="Unix epoch start time")
    end_epoch: int | None = Field(default=None, description="Unix epoch end time")
    time_window_minutes: int = Field(default=5, ge=1, description="Lookback window in minutes")

    @field_validator("locations", mode="before")
    @classmethod
    def normalize_locations(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            value = [value]
        return [str(item).strip() for item in value if str(item).strip()]


class KnowledgeInvocationInput(SharedInvocationInput):
    query: str = Field(..., description="Natural-language search query for mitigation knowledge")
    n_results: int = Field(default=10, ge=1, le=50, description="Number of results to request")
