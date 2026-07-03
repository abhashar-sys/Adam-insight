import httpx
from connect import (
    BASE_URL,
    CHAKRA_X20_HEADER,
    CHAKRA_X20_TOKEN,
    CUSTOMER_BEARER_TOKEN,
    CUSTOMER_CLIENT_ID,
    CUSTOMER_CLIENT_SECRET,
    CUSTOMER_OAUTH_AUDIENCE,
    CUSTOMER_OAUTH_SCOPE,
    CUSTOMER_OAUTH_URL,
    XIPHOS_CA_BUNDLE,
    XIPHOS_CLIENT_CERT,
    XIPHOS_CLIENT_KEY,
)
from models import MitigationResponse, Customer, SingleAttack, AttackEvent


def _timeout() -> httpx.Timeout:
    return httpx.Timeout(15.0)


def _build_xiphos_client() -> httpx.Client:
    kwargs = {
        "base_url": BASE_URL,
        "timeout": _timeout(),
    }
    # When real Xiphos access is available, these env vars enable mTLS.
    if XIPHOS_CLIENT_CERT and XIPHOS_CLIENT_KEY:
        kwargs["cert"] = (XIPHOS_CLIENT_CERT, XIPHOS_CLIENT_KEY)
    if XIPHOS_CA_BUNDLE:
        kwargs["verify"] = XIPHOS_CA_BUNDLE
    return httpx.Client(**kwargs)


def _fetch_customer_bearer_token() -> str | None:
    if CUSTOMER_BEARER_TOKEN:
        return CUSTOMER_BEARER_TOKEN
    if not (CUSTOMER_OAUTH_URL and CUSTOMER_CLIENT_ID and CUSTOMER_CLIENT_SECRET):
        return None

    payload = {
        "grant_type": "client_credentials",
        "client_id": CUSTOMER_CLIENT_ID,
        "client_secret": CUSTOMER_CLIENT_SECRET,
    }
    if CUSTOMER_OAUTH_SCOPE:
        payload["scope"] = CUSTOMER_OAUTH_SCOPE
    if CUSTOMER_OAUTH_AUDIENCE:
        payload["audience"] = CUSTOMER_OAUTH_AUDIENCE

    with httpx.Client(timeout=_timeout()) as client:
        response = client.post(CUSTOMER_OAUTH_URL, data=payload)
        response.raise_for_status()
        token = response.json().get("access_token")
        return token if token else None


def _build_customer_client() -> httpx.Client:
    headers = {}
    token = _fetch_customer_bearer_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=BASE_URL, timeout=_timeout(), headers=headers)


def _build_chakra_client() -> httpx.Client:
    headers = {}
    if CHAKRA_X20_TOKEN:
        headers[CHAKRA_X20_HEADER] = CHAKRA_X20_TOKEN
    return httpx.Client(base_url=BASE_URL, timeout=_timeout(), headers=headers)

def get_mitigation_events() -> MitigationResponse:
    with _build_xiphos_client() as client:
        r = client.get("/xiphos/api/2.2/mitigation/events", params={"withDeviceReports":False})
        r.raise_for_status()
        return MitigationResponse(**r.json())

def get_customers() -> list[Customer]:
    with _build_customer_client() as client:
        r = client.get("/customers/v1/customers", params={"includeIPv6":True})
        r.raise_for_status()
        customers = []
        for item in r.json():
            item["networks"] = item.get("networks") or []
            item["vips"] = item.get("vips") or []
            customers.append(Customer(**item))
        return customers

def get_attack_events(customer_name:str,time_min:str,time_max:str) -> list[AttackEvent]:
    with _build_chakra_client() as client:
        r = client.get(
            "/chakra-rs/v1/attack-events",
            params={
                "customerName":customer_name,
                "timeMin":time_min,
                "timeMax":time_max,
            },
        )
        r.raise_for_status()
        return [AttackEvent(**item) for item in r.json()]

def get_customer_attacks(customer_id:int) -> list[SingleAttack]:
    with _build_chakra_client() as client:
        r = client.get(f"/chakra-rs/v1/customers/{customer_id}/attacks", params={"isActive":True})
        r.raise_for_status()
        return [SingleAttack(**item) for item in r.json()]