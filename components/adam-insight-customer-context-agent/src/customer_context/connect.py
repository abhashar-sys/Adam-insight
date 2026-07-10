import os
from dotenv import load_dotenv

# Load environment variables from a local .env file if present during dev
load_dotenv()

# --- 1. System Target Base URLs ---
# Each service now routes dynamically to its own cluster service endpoint
CUSTOMER_API_URL = os.getenv("CUSTOMER_API_URL", "").rstrip("/")
XIPHOS_URL = os.getenv("XIPHOS_URL", "").rstrip("/")  # Replaces old local Xiphos path
CHAKRA_RS_URL = os.getenv("CHAKRA_RS_URL", "").rstrip("/")          # Replaces old local Chakra path

# --- 2. Xiphos (Traffic Intel) mTLS Config ---
XIPHOS_CLIENT_CERT = os.getenv("XIPHOS_CLIENT_CERT")
XIPHOS_CLIENT_KEY = os.getenv("XIPHOS_CLIENT_KEY")
XIPHOS_CA_BUNDLE = os.getenv("XIPHOS_CA_BUNDLE")

# --- 3. Customer OAuth2 Client Credentials Config ---
CUSTOMER_OAUTH_URL = os.getenv("CUSTOMER_OAUTH_URL")
CUSTOMER_CLIENT_ID = os.getenv("CUSTOMER_CLIENT_ID")
CUSTOMER_CLIENT_SECRET = os.getenv("CUSTOMER_CLIENT_SECRET")
CUSTOMER_OAUTH_SCOPE = os.getenv("CUSTOMER_OAUTH_SCOPE")
CUSTOMER_OAUTH_AUDIENCE = os.getenv("CUSTOMER_OAUTH_AUDIENCE")
# Optional static bearer token override for local/dev troubleshooting.
CUSTOMER_BEARER_TOKEN = os.getenv("CUSTOMER_BEARER_TOKEN")

# --- 4. Chakra x20 Token Auth Config ---
CHAKRA_X20_HEADER = os.getenv("CHAKRA_X20_HEADER", "x20-token")
CHAKRA_X20_TOKEN = os.getenv("CHAKRA_X20_TOKEN")

# --- 5. Configuration Validation Guard (Optional but recommended) ---
# Simple validation to ensure your cluster orchestration injected the required endpoints
if not all([CUSTOMER_API_URL, XIPHOS_URL, CHAKRA_RS_URL]):
    import warnings
    warnings.warn(
        "One or more core service URLs (CUSTOMER_API_URL, XIPHOS_URL, CHAKRA_RS_URL) "
        "are missing. Outbound network requests will fail.", 
        RuntimeWarning
    )