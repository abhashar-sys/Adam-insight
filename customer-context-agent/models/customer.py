from pydantic import BaseModel, Field
from typing import Optional


class Customer(BaseModel):
    customer: str
    networks: list[str] = Field(default_factory=list)
    vips: list[str] = Field(default_factory=list)
    id: int
    accountId: Optional[str] = None
    accountName: Optional[str] = None
    contractId: Optional[str] = None
    inUse: Optional[bool] = None
    region: Optional[str] = None
    location: Optional[str] = None
