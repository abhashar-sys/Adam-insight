from typing import TypedDict,Optional

class AgentState(TypedDict):
    network:str
    locations:list[str]
    customer_context:Optional[dict]