"""Shared fixtures: a full running stack (dashboard <- events <- AST service <- AI engine).

Container mode (Docker Compose sets the URLs): tests talk to the real ``ast_detection``,
``ai_engine`` and ``dashboard`` containers over the internal network.

Local mode (no URLs set): the same three servers are started in-process on free ports,
wired together exactly as in Compose (events flow to the dashboard, the dashboard calls
the AI engine, the AI engine calls the AST service).
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ai_engine.ast_client import ASTServiceClient  # noqa: E402

TOKEN = os.environ.get("SCS_EVENT_TOKEN") or "local-test-token"
CONTAINER_MODE = bool(os.environ.get("DASHBOARD_URL"))


@dataclass
class Stack:
    """URLs of the running services."""

    ast_url: str
    ai_url: str
    dashboard_url: str
    token: str
    container_mode: bool


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start_dashboard(tmp: Path, artifact_dir: Path) -> tuple[object, str, object]:
    import uvicorn

    from dashboard.app import Settings, create_app

    settings = Settings(ai_engine_url="http://127.0.0.1:9", ast_service_url="http://127.0.0.1:9", event_token=TOKEN,
                        artifact_dir=artifact_dir, results_dir=tmp, samples_dir=ROOT / "samples", event_log=None)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(create_app(settings), host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.monotonic() + 10
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.05)
    return server, f"http://127.0.0.1:{port}", settings


@pytest.fixture(scope="session")
def stack(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Stack]:
    if CONTAINER_MODE:
        s = Stack(os.environ["AST_SERVICE_URL"], os.environ["AI_ENGINE_URL"], os.environ["DASHBOARD_URL"], TOKEN, True)
        ASTServiceClient(s.ast_url).wait_until_ready(timeout=60)
        yield s
        return

    from ai_engine.events import EventEmitter as AIEmitter
    from ai_engine.server import start_background_server as start_ai
    from ai_engine.train import TrainingConfig, train_pipeline
    from ast_detection.events import EventEmitter as ASTEmitter
    from ast_detection.server import start_background_server as start_ast

    tmp = tmp_path_factory.mktemp("stack")
    serving_dir = tmp / "serving_artifacts"
    dash, dash_url, settings = _start_dashboard(tmp, serving_dir)
    sink = f"{dash_url}/api/events"
    ast_server, ast_url = start_ast(emitter=ASTEmitter("ast_detection", sink, TOKEN))
    train_pipeline(TrainingConfig(artifact_dir=serving_dir, ast_url=ast_url, n_benign=400, seed=5, tune=False))
    ai_server, ai_url = start_ai(serving_dir, ast_url, AIEmitter("ai_engine", sink, TOKEN))
    settings.ai_engine_url, settings.ast_service_url = ai_url, ast_url
    try:
        yield Stack(ast_url, ai_url, dash_url, TOKEN, False)
    finally:
        for srv in (ai_server, ast_server):
            srv.shutdown()
            srv.server_close()
        dash.should_exit = True


@pytest.fixture(scope="session")
def ast_service_url(stack: Stack) -> str:
    return stack.ast_url


@pytest.fixture(scope="session")
def client(stack: Stack) -> ASTServiceClient:
    return ASTServiceClient(stack.ast_url)


@pytest.fixture(scope="session")
def trained_dir(tmp_path_factory: pytest.TempPathFactory, stack: Stack) -> Path:
    """A small model trained through the (live) AST service, for deterministic assertions."""
    from ai_engine.train import TrainingConfig, train_pipeline

    out = tmp_path_factory.mktemp("artifacts")
    train_pipeline(TrainingConfig(artifact_dir=out, ast_url=stack.ast_url, n_benign=400, seed=11, tune=False))
    return out


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return Path(os.environ.get("SAMPLES_DIR", ROOT / "samples"))
