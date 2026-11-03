FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /build
COPY requirements.txt .
RUN python -m pip install --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    SCOUTX_DASHBOARD__HOST=0.0.0.0 \
    SCOUTX_DASHBOARD__PORT=8000

WORKDIR /app
COPY --from=builder /install /usr/local
COPY dashboard ./dashboard
COPY simulation ./simulation
COPY scripts ./scripts
COPY docs ./docs
COPY render-start.sh ./render-start.sh

RUN groupadd --system scoutx \
    && useradd --system --gid scoutx --home-dir /app scoutx \
    && mkdir -p /app/logs \
    && chown -R scoutx:scoutx /app/logs /app/docs

USER scoutx
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).read()"]

CMD ["bash", "./render-start.sh"]
