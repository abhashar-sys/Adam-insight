from pydantic import BaseModel
from typing import Optional

class MitigationFunction(BaseModel):
    function:str
    config:Optional[dict]=None

class MitigationLocation(BaseModel):
    location:str
    isSuppressed:bool=False
    functions:list[MitigationFunction]=[]

class MitigationNetworkEntry(BaseModel):
    network:Optional[str]=None
    isVip:Optional[bool]=None
    prefix:Optional[str|int]=None
    configs:list[dict]=[]

class MitigationItem(BaseModel):
    id:str|int
    version:Optional[int]=None
    customer:Optional[str]=None
    accountId:Optional[str]=None
    accountName:Optional[str]=None
    isBoa:Optional[bool]=None
    types:list[str]=[]
    state:Optional[str]=None
    tags:list[str]=[]
    preset:Optional[str]=None
    startDate:Optional[str|int]=None
    createdBy:Optional[str]=None
    createdDate:Optional[str|int]=None
    updatedBy:Optional[str]=None
    updatedDate:Optional[str|int]=None
    networks:list[MitigationNetworkEntry]=[]
    isAutoMitigation:Optional[bool]=None

class MitigationResponse(BaseModel):
    items:list[MitigationItem]=[]
    metadata:Optional[dict]=None

#Customer model
class Customer(BaseModel):
    customer:str
    networks:list[str]=[]
    vips:list[str]=[]
    id:int
    accountId:Optional[str]=None
    accountName:Optional[str]=None
    contractId:Optional[str]=None
    inUse:Optional[bool]=None
    region:Optional[str]=None
    location:Optional[str]=None

#Attack models
class SingleAttack(BaseModel):
    id:int
    customerId:int
    startTime:str
    endTime:Optional[str]=None
    routedOffBy:Optional[str]=None
    events:list[int]=[]
    maxAgrPeakBps:Optional[int]=None
    maxAgrPeakPps:Optional[int]=None

class AttackVector(BaseModel):
    type:str
    id:int

class DestinationIP(BaseModel):
    id:int
    ip:Optional[int]=None
    ipAddress:str
    netMask:int

class SuccessStatement(BaseModel):
    successStatementId:int
    successStatementDescription:Optional[str]=None

class AttackEvent(BaseModel):
    id:int
    attackId:int
    startTime:str
    endTime:Optional[str]=None
    graphStartTime:Optional[str]=None
    graphEndTime:Optional[str]=None
    akamaiCaseId:Optional[str]=None
    attackVectors:list[AttackVector]=[]
    nonMitigatedAttackVectors:list[dict]=[]
    agrPeakBps:Optional[int]=None
    agrPeakPps:Optional[int]=None
    successStatement:Optional[SuccessStatement]=None
    customer:Optional[dict]=None
    destinationIPs:list[DestinationIP]=[]
    updateTime:Optional[str]=None
    createdBy:Optional[str]=None
    updatedBy:Optional[str]=None

