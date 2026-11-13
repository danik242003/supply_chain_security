# Test runner: both packages + pytest. Runs the suite against the live ast_detection container
# and the artifacts produced by the trainer container.
FROM python:3.13-slim-trixie

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    ASTMASTER_PATH=/opt/ast_master \
    ARTIFACT_DIR=/artifacts \
    SAMPLES_DIR=/app/samples

COPY ai_engine/requirements.txt /tmp/ai_engine/requirements.txt
COPY tests/requirements.txt /tmp/tests/requirements.txt
RUN pip install --only-binary=:all: -r /tmp/tests/requirements.txt && rm -r /tmp/ai_engine /tmp/tests
RUN useradd --uid 10001 --create-home tester && install -d -o tester -g tester /results
WORKDIR /app
COPY ai_engine ./ai_engine
COPY ast_detection ./ast_detection
COPY samples ./samples
COPY tests ./tests
COPY scanner.py ./scanner.py
COPY pytest.ini ./

USER tester
CMD ["python", "-m", "pytest", "-v", "--junitxml=/results/junit.xml"]
