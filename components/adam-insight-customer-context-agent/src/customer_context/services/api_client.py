from __future__ import annotations
import os
import httpx
import ssl
from customer_context.models import MitigationResponse, Customer, SingleAttack, AttackEvent

# --- 1. CRASH-PROOF ENVIRONMENT LOADER FROM CONFIGMAP FILE ---
CONFIG_FILE_PATH = "/configs/agent-config.env"

if os.path.exists(CONFIG_FILE_PATH):
    print(f"[INFO] Found mounted configuration file at {CONFIG_FILE_PATH}. Parsing keys...")
    try:
        with open(CONFIG_FILE_PATH, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith("#"):
                    continue
                
                # Support both ':' (from your ConfigMap) and '=' delimiters
                delimiter = ":" if ":" in line else "="
                parts = line.split(delimiter, 1)
                
                if len(parts) == 2:
                    key = parts[0].strip()
                    # Strip spaces, standard quotes, and trailing/leading syntax
                    value = parts[1].strip().strip('"').strip("'")
                    os.environ[key] = value
        print("[INFO] Environment variables successfully populated from ConfigMap mount.")
    except Exception as e:
        print(f"[ERROR] Failed to parse configuration file: {str(e)}")
else:
    print(f"[WARNING] Config file not found at {CONFIG_FILE_PATH}. Falling back to container env.")
# =============================================================


def _timeout() -> httpx.Timeout:
    return httpx.Timeout(15.0)


def _build_mtls_client(base_url: str) -> httpx.Client:
    """Helper method to construct a standard client handling both http and mtls https."""
    kwargs = {
        "base_url": base_url,
        "timeout": _timeout(),
    }

    if base_url and base_url.startswith("http://"):
        print(f"[DEBUG] Plain HTTP internal route detected for: {base_url}. Bypassing mTLS.")
        return httpx.Client(**kwargs)

    ca_bundle = os.getenv("CA_CRT_PATH")
    client_cert = os.getenv("TLS_CRT_PATH")
    client_key = os.getenv("TLS_KEY_PATH")

    if os.path.exists(client_cert) and os.path.exists(client_key):
        try:
            # 1. Instantiate a standard SSL Context for Server Authentication
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            
            # 2. Explicitly load the cluster CA bundle so we trust the gateway
            if os.path.exists(ca_bundle):
                ctx.load_verify_locations(cafile=ca_bundle)
            
            # 3. Load the client identity pair so the gateway trusts us
            ctx.load_cert_chain(certfile=client_cert, keyfile=client_key)
            
            # 4. Bind the context directly to the httpx verification pipeline
            kwargs["verify"] = ctx
            print(f"[DEBUG] Robust mTLS SSLContext successfully attached for: {base_url}")
            
        except Exception as e:
            print(f"[WARNING] SSLContext building failed: {str(e)}. Falling back to parameter strings.")
            kwargs["cert"] = (client_cert, client_key)
            if os.path.exists(ca_bundle):
                kwargs["verify"] = ca_bundle
    else:
        print("[WARNING] Certificate files missing on disk. Sending standard unauthenticated client.")

    return httpx.Client(**kwargs)


def _build_xiphos_client() -> httpx.Client:
    return _build_mtls_client(os.getenv("XIPHOS_URL"))


def _build_customer_client() -> httpx.Client:
    return _build_mtls_client(os.getenv("CUSTOMER_API_URL"))


def _build_chakra_client() -> httpx.Client:
    return _build_mtls_client(os.getenv("CHAKRA_RS_URL"))


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
            }
        )
        r.raise_for_status()
        return [AttackEvent(**item) for item in r.json()]


def get_customer_attacks(customer_id: int) -> list[SingleAttack]:
    with _build_chakra_client() as client:
        r = client.get(f"/chakra-rs/v1/customers/{customer_id}/attacks", params={"isActive": True})
        r.raise_for_status()
        return [SingleAttack(**item) for item in r.json()]