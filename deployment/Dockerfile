# Single-stage build for dspy.Trust Security System
FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy all necessary files
COPY pyproject.toml uv.lock ./
COPY src/ ./src/
COPY main.py ./
COPY threat_detector_optimized/ ./threat_detector_optimized/

# Install pip and dependencies directly (simpler approach)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# Create directories for models (will be downloaded on first run or pre-loaded)
RUN mkdir -p /app/models

# Note: Large models are downloaded on first run to avoid long build times
# The application will automatically download required models when started
RUN echo "Models will be downloaded on first run for faster build times"

# Expose port for REST API
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 -c "import requests; requests.get('http://localhost:8000/health')" || exit 1

# Run the FastAPI server
CMD ["python3", "-m", "uvicorn", "trust.api.api:app", "--host", "0.0.0.0", "--port", "8000"]
