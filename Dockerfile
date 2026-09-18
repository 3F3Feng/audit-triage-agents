# Container image for the audit-triage FastAPI service.
# Deliberately non-root and slim, so it satisfies the Pod Security "restricted" profile.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first so this layer caches across code changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application code (only what the service needs at runtime).
COPY tools/ tools/
COPY agents/ agents/
COPY data/ data/
COPY server.py run.py ./

# Bake a synthetic dataset into the image so /events/summary and /triage have data
# without needing a writable mount. It is seeded and reproducible.
RUN python data/generate_sample_logs.py --n 400 --out data/sample_audit_logs.jsonl

# Run as a dedicated non-root user; own /app so report.md can be written at runtime.
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app
USER 10001

EXPOSE 8000

# uvicorn must bind 0.0.0.0 to be reachable from outside the container.
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
