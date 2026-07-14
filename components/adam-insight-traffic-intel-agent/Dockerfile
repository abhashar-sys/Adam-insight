# =============================================================================
# Stage 1 — Builder
# Install dependencies into a clean virtual environment so the final image
# only carries runtime artefacts (no build tools, no pip cache).
# =============================================================================
FROM python:3.11-slim AS builder

# Security: do not run pip as root in the final image
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Copy only the package manifest first to leverage Docker layer caching.
# Dependencies are re-installed only when pyproject.toml changes.
COPY pyproject.toml ./
COPY src/ ./src/

# Build a wheel for the package and install everything into /install
RUN pip install --upgrade pip build \
 && pip install --prefix=/install --no-deps . \
 && pip install --prefix=/install .

# =============================================================================
# Stage 2 — Runtime
# A minimal, hardened image that contains only what is needed to run the agent.
# =============================================================================
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Ensure the installed package is on the Python path
    PYTHONPATH="/app/src"

# Create a non-root user for least-privilege execution
RUN addgroup --system agent && adduser --system --ingroup agent agent

WORKDIR /app

# Copy the pre-built site-packages from the builder stage
COPY --from=builder /install /usr/local

# Copy the source tree (needed for editable imports via PYTHONPATH)
COPY --chown=agent:agent src/ ./src/

# Switch to non-root user
USER agent

# Expose the port the agent listens on (override in Helm values if needed)
EXPOSE 8080

# Healthcheck — calls the /health HTTP endpoint exposed by the FastAPI server.
# `curl` is available in python:3.11-slim; --fail makes curl exit non-zero on 4xx/5xx.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl --silent --fail http://localhost:8080/health || exit 1

# Start the FastAPI server via Uvicorn on port 8080.
# API_HOST / API_PORT / API_LOG_LEVEL can be overridden via Helm env values.
ENTRYPOINT ["uvicorn", "traffic_intel_agent.api:app", "--host", "0.0.0.0", "--port", "8080"]
