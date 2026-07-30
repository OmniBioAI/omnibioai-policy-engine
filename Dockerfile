FROM python:3.11-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Build context is the parent directory (/home/manish/Desktop/machine).

# Install security-audit package so that `audit.logger` is importable.
# The pyproject.toml is currently empty, so fall back to copying the
# audit package directly into site-packages if pip install fails.
COPY omnibioai-security-audit /tmp/omnibioai-security-audit
RUN pip install --no-cache-dir /tmp/omnibioai-security-audit 2>/dev/null || \
    cp -r /tmp/omnibioai-security-audit/audit \
       "$(python -c 'import site; print(site.getsitepackages()[0])')/audit"
RUN rm -rf /tmp/omnibioai-security-audit

# Install service dependencies.
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn \
    "redis[asyncio]" \
    pydantic \
    starlette \
    swagger-ui-bundle \
    aiofiles

# Copy the policy-engine service source.
COPY omnibioai-policy-engine .

EXPOSE 8002

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
