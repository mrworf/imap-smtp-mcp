# syntax=docker/dockerfile:1

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

COPY pyproject.toml ./
COPY src ./src

RUN pip install --upgrade pip \
    && pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN addgroup --system mcp \
    && adduser --system --ingroup mcp --home /home/mcp mcp

WORKDIR /app

COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* \
    && rm -rf /wheels

USER mcp:mcp

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import json,os,ssl,urllib.request; port=os.getenv('MCP_PORT','8000'); https=os.getenv('MCP_INTERNAL_HTTPS','').lower() in {'1','true','yes','on'}; url=f\"{'https' if https else 'http'}://127.0.0.1:{port}/readyz\"; ctx=ssl._create_unverified_context() if https else None; json.load(urllib.request.urlopen(url, timeout=3, context=ctx))['ready']"

CMD ["python", "-m", "imap_smtp_mcp.server"]
