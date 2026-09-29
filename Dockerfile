# RansomShield AI — Production Backend Dockerfile
# Phase 5: Production Hardening & Deployment Readiness
#
# Multi-stage container build with non-root security context.

FROM python:3.11-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# --- Final Production Image ---
FROM python:3.11-slim AS runner

WORKDIR /app

# Create non-root system user for production execution
RUN groupadd -g 10001 ransomshield && \
    useradd -u 10001 -g ransomshield -m -s /bin/bash ransomshield

# Copy installed dependencies from builder
COPY --from=builder /root/.local /home/ransomshield/.local
ENV PATH=/home/ransomshield/.local/bin:$PATH

# Copy application source code
COPY --chown=ransomshield:ransomshield backend/ /app/backend/
COPY --chown=ransomshield:ransomshield agent/ /app/agent/
COPY --chown=ransomshield:ransomshield ml/ /app/ml/

# Create runtime directories for logs and safe quarantine store
RUN mkdir -p /app/data/quarantine /app/logs && \
    chown -R ransomshield:ransomshield /app/data /app/logs

USER ransomshield

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ENVIRONMENT=production \
    PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/v1/health/live').read()" || exit 1

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
