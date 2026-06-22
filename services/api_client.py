import httpx
from connect import BASE_URL
from models import MitigationResponse,Customer,SingleAttack,AttackEvent

def get_mitigation_events() -> MitigationResponse:
    r=httpx.get(f"{BASE_URL}/xiphos/api/2.2/mitigation/events",
                params={"withDeviceReports":False},timeout=15.0)
    r.raise_for_status()
    return MitigationResponse(**r.json())

def get_customers() -> list[Customer]:
    r=httpx.get(f"{BASE_URL}/customers/v1/customers",timeout=15.0)
    r.raise_for_status()
    return [Customer(**item) for item in r.json()]

def get_attack_events(customer_name:str,time_min:str,time_max:str) -> list[AttackEvent]:
    r=httpx.get(f"{BASE_URL}/chakra-rs/v1/attack-events",
                params={"customerName":customer_name,
                        "timeMin":time_min,
                        "timeMax":time_max},timeout=15.0)
    r.raise_for_status()
    return [AttackEvent(**item) for item in r.json()]

def get_customer_attacks(customer_id:int) -> list[SingleAttack]:
    r=httpx.get(f"{BASE_URL}/chakra-rs/v1/customers/{customer_id}/attacks",
                params={"isActive":True},timeout=15.0)
    r.raise_for_status()
    return [SingleAttack(**item) for item in r.json()]