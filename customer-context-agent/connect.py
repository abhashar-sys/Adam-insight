import os
from dotenv import load_dotenv

load_dotenv()

BASE_URL = os.getenv("API_BASE_URL") or os.getenv("MOCK_BASE_URL") or ""

# Xiphos mTLS config
XIPHOS_CLIENT_CERT = os.getenv("XIPHOS_CLIENT_CERT")
XIPHOS_CLIENT_KEY = os.getenv("XIPHOS_CLIENT_KEY")
XIPHOS_CA_BUNDLE = os.getenv("XIPHOS_CA_BUNDLE")

# Customer OAuth2 Client Credentials config
CUSTOMER_OAUTH_URL = os.getenv("CUSTOMER_OAUTH_URL")
CUSTOMER_CLIENT_ID = os.getenv("CUSTOMER_CLIENT_ID")
CUSTOMER_CLIENT_SECRET = os.getenv("CUSTOMER_CLIENT_SECRET")
CUSTOMER_OAUTH_SCOPE = os.getenv("CUSTOMER_OAUTH_SCOPE")
CUSTOMER_OAUTH_AUDIENCE = os.getenv("CUSTOMER_OAUTH_AUDIENCE")
# Optional static bearer token override for local/dev troubleshooting.
CUSTOMER_BEARER_TOKEN = os.getenv("CUSTOMER_BEARER_TOKEN")

# Chakra x20 token auth config
CHAKRA_X20_HEADER = os.getenv("CHAKRA_X20_HEADER", "x20-token")
CHAKRA_X20_TOKEN = os.getenv("CHAKRA_X20_TOKEN")