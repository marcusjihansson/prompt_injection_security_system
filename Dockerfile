# Demo-friendly Dockerfile for the Threat Detection API
FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy Python project files
COPY pyproject.toml README.md /app/
COPY threat_system /app/threat_system
COPY threat_types /app/threat_types
COPY production /app/production
COPY tests /app/tests

# Install dependencies
# Use pip to install for simplicity in container
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir fastapi uvicorn pytest \
    && pip install --no-cache-dir -e .

EXPOSE 8000

# Default to offline mode (no OpenRouter) for safe demos
ENV OPENROUTER_API_KEY=""

CMD ["uvicorn", "production.api:app", "--host", "0.0.0.0", "--port", "8000"]
