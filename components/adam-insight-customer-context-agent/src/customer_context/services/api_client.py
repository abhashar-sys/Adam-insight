from __future__ import annotations
import httpx
from customer_context.connect import (
    CUSTOMER_API_URL,
    XIPHOS_URL,
    CHAKRA_RS_URL,
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
from customer_context.models import MitigationResponse, Customer, SingleAttack, AttackEvent


def _timeout() -> httpx.Timeout:
    return httpx.Timeout(15.0)


def _build_xiphos_client() -> httpx.Client:
    kwargs = {
        "base_url": XIPHOS_URL,
        "timeout": _timeout(),
    }
    # 1. Xiphos mTLS Authentication
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

    # Ensure the OAuth token request itself trusts the cluster's CA bundle
    client_kwargs = {"timeout": _timeout()}
    if XIPHOS_CA_BUNDLE:
        client_kwargs["verify"] = XIPHOS_CA_BUNDLE

    with httpx.Client(**client_kwargs) as client:
        response = client.post(CUSTOMER_OAUTH_URL, data=payload)
        response.raise_for_status()
        token = response.json().get("access_token")
        return token if token else None


def _build_customer_client() -> httpx.Client:
    headers = {}
    token = _fetch_customer_bearer_token()
    if token:
        # 2. Customer API Bearer Token Authentication
        headers["Authorization"] = f"Bearer {token}"
        
    kwargs = {
        "base_url": CUSTOMER_API_URL,
        "timeout": _timeout(),
        "headers": headers,
    }
    # Trust the internal cluster certificate authority bundle
    if XIPHOS_CA_BUNDLE:
        kwargs["verify"] = XIPHOS_CA_BUNDLE
        
    return httpx.Client(**kwargs)


def _build_chakra_client() -> httpx.Client:
    headers = {}
    if CHAKRA_X20_TOKEN:
        # 3. Chakra-RS Specialized X20 Header Authentication
        headers[CHAKRA_X20_HEADER] = CHAKRA_X20_TOKEN
        
    kwargs = {
        "base_url": CHAKRA_RS_URL,
        "timeout": _timeout(),
        "headers": headers,
    }
    # Trust the internal cluster certificate authority bundle
    if XIPHOS_CA_BUNDLE:
        kwargs["verify"] = XIPHOS_CA_BUNDLE
        
    return httpx.Client(**kwargs)

def get_mitigation_events() -> MitigationResponse:
    with _build_xiphos_client() as client:
        r = client.get("/xiphos/api/2.2/mitigation/events", params={"withDeviceReports": False})
        r.raise_for_status()
        return MitigationResponse(**r.json())

def get_customers() -> list[Customer]:
    with _build_customer_client() as client:
        r = client.get("/customers/v1/customers", params={"includeIPv6": True})
        r.raise_for_status()
        customers = []
        for item in r.json():
            item["networks"] = item.get("networks") or []
            item["vips"] = item.get("vips") or []
            customers.append(Customer(**item))
        return customers

def get_attack_events(customer_name: str, time_min: str, time_max: str) -> list[AttackEvent]:
    with _build_chakra_client() as client:
        r = client.get(
            "/chakra-rs/v1/attack-events",
            params={
                "customerName": customer_name,
                "timeMin": time_min,
                "timeMax": time_max,
            },
        )
        r.raise_for_status()
        return [AttackEvent(**item) for item in r.json()]

def get_customer_attacks(customer_id: int) -> list[SingleAttack]:
    with _build_chakra_client() as client:
        r = client.get(f"/chakra-rs/v1/customers/{customer_id}/attacks", params={"isActive": True})
        r.raise_for_status()
        return [SingleAttack(**item) for item in r.json()]