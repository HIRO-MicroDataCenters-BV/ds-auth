FROM python:3.12-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install ds-auth from the parent repo. Build context in docker-compose is set
# to the repo root (../../..) so the ds_auth package + pyproject.toml are
# available at /src.
COPY ds_auth /src/ds_auth
COPY pyproject.toml README.md /src/
RUN pip install --no-cache-dir /src

# Service-specific deps
COPY tests/integration/test_service/requirements.txt /app/req.txt
RUN pip install --no-cache-dir -r /app/req.txt

COPY tests/integration/test_service/main.py /app/main.py

EXPOSE 9100

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -fsS http://localhost:9100/health-check/ || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9100"]
