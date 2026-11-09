# =========================================================
# SecurePatch AI Security Platform - Backend Dockerfile
# =========================================================
FROM python:3.11-slim

WORKDIR /app

# Install git, curl, and essential system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir bandit pytest

# Copy backend API, source engine modules, and test sample repository
COPY backend/ ./backend/
COPY src/ ./src/
COPY sample_repo/ ./sample_repo/

# Create persistent workspace directory structures
RUN mkdir -p /app/workspace/repositories /app/workspace/sandbox_runs /app/workspace/sandboxes

# Configure Python environment
ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Start production uvicorn server
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
