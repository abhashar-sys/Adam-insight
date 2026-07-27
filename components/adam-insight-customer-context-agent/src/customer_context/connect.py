import os

# Base URLs
XIPHOS_URL = os.getenv("XIPHOS_URL")
CUSTOMER_API_URL = os.getenv("CUSTOMER_API_URL")
CHAKRA_RS_URL = os.getenv("CHAKRA_RS_URL")

# Unified mTLS File Paths (Pointed to the mounted volume folder)
XIPHOS_CA_BUNDLE = os.getenv("CA_CRT_PATH")
XIPHOS_CLIENT_CERT = os.getenv("TLS_CRT_PATH")
XIPHOS_CLIENT_KEY = os.getenv("TLS_KEY_PATH")