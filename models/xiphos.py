from pydantic import BaseModel
from typing import Optional


class MitigationFunction(BaseModel):
    function: str
    config: Optional[dict] = None


class MitigationLocation(BaseModel):
    location: str
    isSuppressed: bool = False
    functions: list[MitigationFunction] = []


class MitigationNetworkEntry(BaseModel):
    network: Optional[str] = None
    isVip: Optional[bool] = None
    prefix: Optional[str | int] = None
    configs: list[dict] = []


class MitigationItem(BaseModel):
    id: str | int
    version: Optional[int] = None
    customer: Optional[str] = None
    accountId: Optional[str] = None
    accountName: Optional[str] = None
    isBoa: Optional[bool] = None
    types: list[str] = []
    state: Optional[str] = None
    tags: list[str] = []
    preset: Optional[str] = None
    startDate: Optional[str | int] = None
    createdBy: Optional[str] = None
    createdDate: Optional[str | int] = None
    updatedBy: Optional[str] = None
    updatedDate: Optional[str | int] = None
    networks: list[MitigationNetworkEntry] = []
    isAutoMitigation: Optional[bool] = None


class MitigationResponse(BaseModel):
    items: list[MitigationItem] = []
    metadata: Optional[dict] = None
