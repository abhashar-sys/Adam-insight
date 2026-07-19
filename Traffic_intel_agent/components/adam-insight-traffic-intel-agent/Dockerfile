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

# Healthcheck — adjust the endpoint when your HTTP server is wired up
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import traffic_intel_agent; print('ok')" || exit 1

# Default entrypoint delegates to the CLI script defined in pyproject.toml.
# Override with `args` in the Helm deployment if you need a different command.
ENTRYPOINT ["python", "-m", "traffic_intel_agent.main"]
