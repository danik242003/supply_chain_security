"""AI engine HTTP API (standard library server; the models are scikit-learn).

Endpoints:
    ``GET  /health``  -> model status, training summary, AST service reachability
    ``POST /assess``  -> body ``{"packages": [{"name", "files", "metadata"?, "request_id"?}]}``
                         (or a single package object) -> ``{"reports": [...]}``
    ``POST /reload``  -> reload artifacts from disk (after retraining)

Every assessment calls the AST detection service, scores the returned features and
emits ``ai.assess.*`` telemetry events to the dashboard.

Run with::

    python -m ai_engine.server --host 0.0.0.0 --port 8100
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ai_engine import __version__
from ai_engine.ast_client import ASTServiceClient, ASTServiceError
from ai_engine.config import ARTIFACT_DIR
from ai_engine.data.loader import normalize_metadata
from ai_engine.events import EventEmitter
from ai_engine.features.pipeline import FeatureSchemaError
from ai_engine.predict import RiskEngine

logger = logging.getLogger("ai_engine.server")

MAX_BODY_BYTES = 64 * 1024 * 1024
MAX_PACKAGES = 100


class _ClientError(ValueError):
    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


class EngineState:
    """Holds the loaded :class:`RiskEngine`; loads lazily so the server can start before training ends."""

    def __init__(self, artifact_dir: Path, client: ASTServiceClient, emitter: EventEmitter) -> None:
        self.artifact_dir = artifact_dir
        self.client = client
        self.emitter = emitter
        self._engine: RiskEngine | None = None
        self._lock = threading.Lock()
        self.load_error: str | None = None
        self.assessed = 0

    def engine(self, reload: bool = False) -> RiskEngine:
        """Return the loaded engine, loading (or reloading) artifacts from disk if needed."""
        with self._lock:
            if self._engine is None or reload:
                try:
                    self._engine = RiskEngine(self.artifact_dir, self.client, self.emitter)
                    self.load_error = None
                    self.emitter.emit("ai.model.loaded", trained_at=self._engine.scorer.metadata.get("created_at"))
                except Exception as exc:
                    self.load_error = f"{type(exc).__name__}: {exc}"
                    raise
            return self._engine

    def training_report(self) -> dict[str, Any] | None:
        """Summary of ``training_report.json`` (verification + metrics), or ``None`` if absent."""
        path = self.artifact_dir / "training_report.json"
        if not path.exists():
            return None
        report = json.loads(path.read_text(encoding="utf-8"))
        return {"layer_verification": report.get("layer_verification"),
                "test_metrics": {k: report["test_metrics"][k] for k in ("hybrid", "static_only", "supervised_only",
                                                                         "anomaly_only")},
                "training_seconds": report.get("training_seconds"),
                "dataset": report.get("dataset")}


def _parse_packages(body: Any) -> list[dict[str, Any]]:
    packages = body.get("packages") if isinstance(body, dict) and "packages" in body else [body]
    if not isinstance(packages, list) or not packages:
        raise _ClientError("'packages' must be a non-empty list")
    if len(packages) > MAX_PACKAGES:
        raise _ClientError(f"too many packages (max {MAX_PACKAGES})", 413)
    out = []
    for p in packages:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("files"), dict) \
                or not p["files"]:
            raise _ClientError("each package needs 'name' (str) and non-empty 'files' (object)")
        out.append({"name": p["name"], "files": p["files"], "metadata": normalize_metadata(p.get("metadata")),
                    **({"request_id": str(p["request_id"])[:64]} if p.get("request_id") else {})})
    return out


def make_handler(state: EngineState) -> type[BaseHTTPRequestHandler]:
    """Request handler bound to ``state``."""

    class Handler(BaseHTTPRequestHandler):
        server_version = f"ai-engine/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:
            """Route http.server access logs to ``logging`` at DEBUG level."""
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            """Serve ``/health``: model status, AST service reachability, training summary."""
            if self.path.rstrip("/") != "/health":
                self._send(404, {"error": "not found"})
                return
            try:
                engine = state.engine()
                model = {"loaded": True, "trained_at": engine.scorer.metadata.get("created_at"),
                         "decision_threshold": engine.scorer.config.decision_threshold,
                         "ast_features": len(engine.scorer.pipeline.ast_features_)}
            except Exception:
                model = {"loaded": False, "error": state.load_error}
            try:
                ast = {"reachable": True, "backend": state.client.health()["backend"]}
            except ASTServiceError as exc:
                ast = {"reachable": False, "error": str(exc)}
            ok = model["loaded"] and ast["reachable"]
            self._send(200 if ok else 503, {
                "status": "ok" if ok else "degraded", "service_version": __version__, "model": model,
                "ast_service": ast, "assessed": state.assessed, "training": state.training_report(),
                "events": {"enabled": state.emitter.enabled, "sent": state.emitter.sent,
                           "dropped": state.emitter.dropped},
            })

        def do_POST(self) -> None:  # noqa: N802
            """Serve ``/assess`` (score packages via the AST service) and ``/reload``."""
            route = self.path.rstrip("/")
            try:
                if route == "/reload":
                    state.engine(reload=True)
                    self._send(200, {"status": "reloaded"})
                    return
                if route != "/assess":
                    self._send(404, {"error": "not found"})
                    return
                length = int(self.headers.get("Content-Length") or 0)
                if not 0 < length <= MAX_BODY_BYTES:
                    raise _ClientError("missing or oversized body", 413 if length else 400)
                try:
                    body = json.loads(self.rfile.read(length))
                except json.JSONDecodeError as exc:
                    raise _ClientError(f"invalid JSON: {exc.msg}") from exc
                packages = _parse_packages(body)
                reports = state.engine().assess(packages)
                state.assessed += len(reports)
                self._send(200, {"reports": reports})
            except _ClientError as exc:
                self._send(exc.status, {"error": str(exc)})
            except ASTServiceError as exc:
                self._send(502, {"error": f"AST service: {exc}"})
            except (FileNotFoundError, FeatureSchemaError) as exc:
                self._send(503, {"error": str(exc)})
            except Exception:
                logger.exception("assessment failed")
                self._send(500, {"error": "internal error"})

    return Handler


def make_server(host: str = "127.0.0.1", port: int = 8100, artifact_dir: Path = ARTIFACT_DIR,
                ast_url: str | None = None, emitter: EventEmitter | None = None) -> ThreadingHTTPServer:
    """Create (not start) the server. ``port=0`` picks a free port."""
    state = EngineState(Path(artifact_dir), ASTServiceClient(ast_url, timeout=60),
                        emitter or EventEmitter("ai_engine"))
    server = ThreadingHTTPServer((host, port), make_handler(state))
    server.daemon_threads = True
    return server


def start_background_server(artifact_dir: Path, ast_url: str, emitter: EventEmitter | None = None,
                            host: str = "127.0.0.1") -> tuple[ThreadingHTTPServer, str]:
    """Run on a daemon thread (tests). Returns ``(server, base_url)``."""
    server = make_server(host, 0, artifact_dir, ast_url, emitter)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{host}:{server.server_address[1]}"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="AI engine API")
    ap.add_argument("--host", default=os.environ.get("AI_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("AI_PORT", 8100)))
    ap.add_argument("--artifacts", type=Path, default=ARTIFACT_DIR)
    ap.add_argument("--ast-url")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    server = make_server(args.host, args.port, args.artifacts, args.ast_url)
    logger.info("AI engine listening on http://%s:%d (artifacts %s)", args.host, args.port, args.artifacts)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
