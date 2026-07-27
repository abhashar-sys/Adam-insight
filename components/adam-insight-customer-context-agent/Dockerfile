# Use a lightweight, official Python runtime
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy the packaging configuration files first
# This allows Docker to cache your dependencies if these files don't change
COPY pyproject.toml README.md ./

# Copy your actual source code folder into the container
COPY src/ ./src/

# If you need your openapi.yaml or .env at runtime, make sure they are copied over:
# COPY src/customer_context/openapi.yaml ./src/customer_context/openapi.yaml

# Install your package and its core dependencies from pyproject.toml
# --no-cache-dir keeps the final container image lightweight
RUN pip install --no-cache-dir .

# Expose the application port
EXPOSE 8013

# Run the Uvicorn server using package dot-notation
CMD ["uvicorn", "customer_context.app:app", "--host", "0.0.0.0", "--port", "8013"]