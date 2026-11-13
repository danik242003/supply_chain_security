# Admin dashboard: FastAPI + WebSockets. Receives telemetry from both services, proxies submissions to ai_engine.
FROM python:3.13-slim-trixie

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DASHBOARD_HOST=0.0.0.0 \
    DASHBOARD_PORT=8501 \
    SAMPLES_DIR=/app/samples \
    EVENT_LOG=/data/events.jsonl

COPY dashboard/requirements.txt /tmp/requirements.txt
RUN pip install --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin dash && install -d -o dash -g dash /data
WORKDIR /app
COPY dashboard ./dashboard
COPY samples ./samples

USER dash
EXPOSE 8501
HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/api/events?limit=1', timeout=2)"]
CMD ["python", "-m", "dashboard.app"]
