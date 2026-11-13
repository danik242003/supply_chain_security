# AI engine: Isolation Forest + Random Forest + hybrid scorer. Talks to ast_detection over HTTP only.
FROM python:3.13-slim-trixie

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ARTIFACT_DIR=/artifacts \
    SAMPLES_DIR=/app/samples \
    AST_SERVICE_URL=http://ast_detection:8000 \
    AI_HOST=0.0.0.0 \
    AI_PORT=8100

COPY ai_engine/requirements.txt /tmp/requirements.txt
RUN pip install --only-binary=:all: -r /tmp/requirements.txt && rm /tmp/requirements.txt

# /artifacts is pre-created with the right owner so the named volume inherits it.
RUN useradd --uid 10001 --create-home aiengine && install -d -o aiengine -g aiengine /artifacts
WORKDIR /app
COPY ai_engine ./ai_engine
COPY samples ./samples
COPY scanner.py ./scanner.py

USER aiengine
EXPOSE 8100
# Default: serve the models. docker-compose also runs this image as the one-shot `trainer`.
CMD ["python", "-m", "ai_engine.server"]
