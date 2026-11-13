# AST detection service: stdlib-only static analysis API.
# AST Master is NOT copied in: docker-compose mounts the local desktop copy read-only at /opt/ast_master.
FROM python:3.13-slim-trixie

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ASTMASTER_PATH=/opt/ast_master \
    AST_HOST=0.0.0.0 \
    AST_PORT=8000

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin astsvc
WORKDIR /app
COPY ast_detection ./ast_detection

USER astsvc
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=3s --retries=12 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]
CMD ["python", "-m", "ast_detection.server"]
