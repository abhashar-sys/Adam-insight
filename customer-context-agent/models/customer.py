from pydantic import BaseModel
from typing import Optional


class Customer(BaseModel):
    customer: str
    networks: list[str] = []
    vips: list[str] = []
    id: int
    accountId: Optional[str] = None
    accountName: Optional[str] = None
    contractId: Optional[str] = None
    inUse: Optional[bool] = None
    region: Optional[str] = None
    location: Optional[str] = None
