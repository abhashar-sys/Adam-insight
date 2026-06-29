from pydantic import BaseModel
from typing import Optional


class SingleAttack(BaseModel):
    id: int
    customerId: int
    startTime: str
    endTime: Optional[str] = None
    routedOffBy: Optional[str] = None
    events: list[int] = []
    maxAgrPeakBps: Optional[int] = None
    maxAgrPeakPps: Optional[int] = None


class AttackVector(BaseModel):
    type: str
    id: int


class DestinationIP(BaseModel):
    id: int
    ip: Optional[int] = None
    ipAddress: str
    netMask: int


class SuccessStatement(BaseModel):
    successStatementId: int
    successStatementDescription: Optional[str] = None


class AttackEvent(BaseModel):
    id: int
    attackId: int
    startTime: str
    endTime: Optional[str] = None
    graphStartTime: Optional[str] = None
    graphEndTime: Optional[str] = None
    akamaiCaseId: Optional[str] = None
    attackVectors: list[AttackVector] = []
    nonMitigatedAttackVectors: list[dict] = []
    agrPeakBps: Optional[int] = None
    agrPeakPps: Optional[int] = None
    successStatement: Optional[SuccessStatement] = None
    customer: Optional[dict] = None
    destinationIPs: list[DestinationIP] = []
    updateTime: Optional[str] = None
    createdBy: Optional[str] = None
    updatedBy: Optional[str] = None
