"""Lightweight JSON-over-HTTP API exposing the AST analyzer (standard library only).

Endpoints:
    ``GET  /health``          -> ``{"status": "ok", "backend": {...}, "feature_names": [...]}``
    ``POST /analyze``         -> body ``{"name": str, "files": {path: source}}``
    ``POST /analyze/batch``   -> body ``{"packages": [{"name": ..., "files": {...}}, ...]}``

Each package may carry an optional ``request_id`` used to correlate telemetry events
(``ast.parse.started`` / ``ast.parse.completed``) pushed to the dashboard.

Submitted code is parsed, never executed. Run with::

    python -m ast_detection.server --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from ast_detection import FEATURE_SCHEMA_VERSION, __version__
from ast_detection.analyzer import PackageAnalyzer, astmaster_feature_names
from ast_detection.events import EventEmitter
from ast_detection.extractors import aggregate_package
from ast_detection.parser import AstMasterParser

logger = logging.getLogger("ast_detection.server")

MAX_BODY_BYTES = int(os.environ.get("AST_MAX_BODY_BYTES", 64 * 1024 * 1024))
MAX_FILES_PER_PACKAGE = 500
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_BATCH = 500
#: Source shipped to the dashboard per event, so it can render code with risky nodes highlighted.
EVENT_SOURCE_CHARS_PER_FILE = 30_000
EVENT_SOURCE_CHARS_TOTAL = 150_000


class RequestError(ValueError):
    """Client error mapped to HTTP 400/413."""

    def __init__(self, message: str, status: int = 400) -> None:
        super().__init__(message)
        self.status = status


def analyze_with_events(analyzer: PackageAnalyzer, emitter: EventEmitter, name: str, files: dict[str, str],
                        request_id: str | None) -> dict[str, Any]:
    """Run one analysis, bracketing it with telemetry events."""
    emitter.emit("ast.parse.started", request_id=request_id, package=name,
                 files=[{"path": p, "bytes": len(src)} for p, src in sorted(files.items())])
    result = analyzer.analyze(name, files)
    result["request_id"] = request_id
    if emitter.enabled:
        budget = EVENT_SOURCE_CHARS_TOTAL
        sources = {}
        for path in sorted(files):
            if path.endswith((".py", ".pyw")) and budget > 0:
                text = files[path][:min(EVENT_SOURCE_CHARS_PER_FILE, budget)]
                sources[path] = text
                budget -= len(text)
        emitter.emit(
            "ast.parse.completed", request_id=request_id, package=name,
            duration_ms=result["duration_ms"], static_risk=result["static_risk"], backend=result["backend"],
            risky_nodes=result["risky_nodes"], findings=result["findings"], files=result["files"],
            n_features=len(result["features"]),
            nonzero_features=sum(1 for v in result["features"].values() if v),
            sources=sources,
        )
    return result


def _validate_package(obj: Any) -> tuple[str, dict[str, str]]:
    if not isinstance(obj, dict):
        raise RequestError("package must be an object")
    name, files = obj.get("name"), obj.get("files")
    if not isinstance(name, str) or not name.strip():
        raise RequestError("'name' must be a non-empty string")
    if not isinstance(files, dict) or not files:
        raise RequestError("'files' must be a non-empty object of path -> source")
    if len(files) > MAX_FILES_PER_PACKAGE:
        raise RequestError(f"too many files (max {MAX_FILES_PER_PACKAGE})", 413)
    for path, source in files.items():
        if not isinstance(path, str) or not isinstance(source, str):
            raise RequestError("file paths and sources must be strings")
        if ".." in path.split("/") or path.startswith("/"):
            raise RequestError(f"unsafe path: {path!r}")
        if len(source.encode("utf-8", "surrogatepass")) > MAX_FILE_BYTES:
            raise RequestError(f"file too large: {path}", 413)
    return name.strip(), files


def make_handler(analyzer: PackageAnalyzer, emitter: EventEmitter) -> type[BaseHTTPRequestHandler]:
    """Build a request handler class bound to ``analyzer`` and ``emitter``."""
    feature_names = sorted(aggregate_package([]).keys()) + astmaster_feature_names()

    class Handler(BaseHTTPRequestHandler):
        server_version = f"ast-detection/{__version__}"

        def log_message(self, fmt: str, *args: Any) -> None:  # route to logging
            """Route http.server access logs to ``logging`` at DEBUG level."""
            logger.debug("%s - %s", self.address_string(), fmt % args)

        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self) -> None:  # noqa: N802
            """Serve ``/health``: backend info, feature names and telemetry counters."""
            if self.path.rstrip("/") == "/health":
                self._send(200, {
                    "status": "ok",
                    "service_version": __version__,
                    "schema_version": FEATURE_SCHEMA_VERSION,
                    "backend": analyzer.parser.backend_info(),
                    "feature_names": feature_names,
                    "events": {"enabled": emitter.enabled, "sent": emitter.sent, "dropped": emitter.dropped},
                })
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            """Serve ``/analyze`` and ``/analyze/batch``; client errors map to 400/413, never a traceback."""
            try:
                length = int(self.headers.get("Content-Length") or 0)
                if length <= 0:
                    raise RequestError("empty body")
                if length > MAX_BODY_BYTES:
                    raise RequestError("body too large", 413)
                try:
                    body = json.loads(self.rfile.read(length))
                except json.JSONDecodeError as exc:
                    raise RequestError(f"invalid JSON: {exc.msg}") from exc
                route = self.path.rstrip("/")
                if route == "/analyze":
                    name, files = _validate_package(body)
                    self._send(200, analyze_with_events(analyzer, emitter, name, files, _request_id(body)))
                elif route == "/analyze/batch":
                    packages = body.get("packages") if isinstance(body, dict) else None
                    if not isinstance(packages, list) or not packages:
                        raise RequestError("'packages' must be a non-empty list")
                    if len(packages) > MAX_BATCH:
                        raise RequestError(f"batch too large (max {MAX_BATCH})", 413)
                    validated = [(*_validate_package(p), _request_id(p)) for p in packages]
                    self._send(200, {"results": [analyze_with_events(analyzer, emitter, n, f, r)
                                                 for n, f, r in validated]})
                else:
                    self._send(404, {"error": "not found"})
            except RequestError as exc:
                self._send(exc.status, {"error": str(exc)})
            except Exception:  # never leak a traceback to the client
                logger.exception("analysis failed")
                self._send(500, {"error": "internal error"})

    return Handler


def _request_id(obj: Any) -> str | None:
    rid = obj.get("request_id") if isinstance(obj, dict) else None
    return str(rid)[:64] if rid else None


def make_server(host: str = "127.0.0.1", port: int = 8000, analyzer: PackageAnalyzer | None = None,
                emitter: EventEmitter | None = None) -> ThreadingHTTPServer:
    """Create (but do not start) the HTTP server. ``port=0`` picks a free port."""
    server = ThreadingHTTPServer((host, port), make_handler(analyzer or PackageAnalyzer(),
                                                            emitter or EventEmitter("ast_detection")))
    server.daemon_threads = True
    return server


def start_background_server(host: str = "127.0.0.1", port: int = 0,
                            emitter: EventEmitter | None = None) -> tuple[ThreadingHTTPServer, str]:
    """Start the service on a daemon thread (used by tests). Returns ``(server, base_url)``."""
    server = make_server(host, port, emitter=emitter)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{host}:{server.server_address[1]}"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="AST detection service")
    parser.add_argument("--host", default=os.environ.get("AST_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AST_PORT", 8000)))
    parser.add_argument("--require-astmaster", action="store_true",
                        default=os.environ.get("ASTMASTER_REQUIRED") == "1",
                        help="Fail at startup if AST Master cannot be loaded")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    analyzer = PackageAnalyzer(AstMasterParser(required=args.require_astmaster))
    server = make_server(args.host, args.port, analyzer)
    logger.info("Listening on http://%s:%d (astmaster available=%s)", args.host, args.port, analyzer.parser.available)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
