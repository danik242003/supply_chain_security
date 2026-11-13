"""Real-time admin dashboard (FastAPI + WebSockets).

Data flow::

    ast_detection ──POST /api/events──┐
    ai_engine     ──POST /api/events──┼──► EventHub ──WebSocket /ws──► browser (live view)
    trainer       ──POST /api/events──┘
    browser ──POST /api/submit──► dashboard ──POST /assess──► ai_engine ──► ast_detection

Endpoints:
    GET  /                       live dashboard (static/index.html)
    WS   /ws                     backlog + live event stream
    POST /api/events             telemetry ingest (shared-token protected)
    GET  /api/events             recent events (filter: ``request_id``, ``type``)
    GET  /api/health             aggregated health of all services + training + test results
    POST /api/submit             submit a package {name, files, metadata?} for assessment
    GET  /api/scans/latest       latest scan report (scanner.py run or dashboard upload, whichever is newer)
    POST /api/scan/upload        scan uploaded Python files / a folder ({"files": {relpath: source}}); .py only
    GET  /api/samples            bundled mock payloads
    POST /api/samples/{name}     submit a bundled sample

All package content is untrusted: the UI renders it with ``textContent`` only.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import os
import posixpath
import time
import uuid
from collections import Counter
import xml.etree.ElementTree as ET
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

logger = logging.getLogger("dashboard")

STATIC_DIR = Path(__file__).resolve().parent / "static"
TOKEN_HEADER = "X-SCS-Token"
MAX_EVENTS_PER_POST = 500
MAX_SUBMIT_FILES = 200
MAX_SUBMIT_BYTES = 5 * 1024 * 1024
MAX_UPLOAD_FILES = 1000
MAX_UPLOAD_FILE_BYTES = 2 * 1024 * 1024
MAX_UPLOAD_TOTAL_BYTES = 50 * 1024 * 1024
UPLOAD_BATCH = 25
UPLOAD_SUFFIXES = (".py",)
_VERDICT_ORDER = {"MALICIOUS": 0, "SUSPICIOUS": 1, "ERROR": 2, "BENIGN": 3, "NOT_ANALYZED": 4}
_SAMPLE_SUFFIXES = (".py", ".pyw", ".pth", ".cfg", ".toml", ".txt")


@dataclass
class Settings:
    """Dashboard configuration (environment-driven)."""

    ai_engine_url: str = field(default_factory=lambda: os.environ.get("AI_ENGINE_URL", "http://127.0.0.1:8100"))
    ast_service_url: str = field(default_factory=lambda: os.environ.get("AST_SERVICE_URL", "http://127.0.0.1:8000"))
    event_token: str = field(default_factory=lambda: os.environ.get("SCS_EVENT_TOKEN", ""))
    artifact_dir: Path = field(default_factory=lambda: Path(os.environ.get("ARTIFACT_DIR", "/artifacts")))
    results_dir: Path = field(default_factory=lambda: Path(os.environ.get("TEST_RESULTS_DIR", "/results")))
    reports_dir: Path = field(default_factory=lambda: Path(os.environ.get("REPORTS_DIR", "/reports")))
    samples_dir: Path = field(default_factory=lambda: Path(os.environ.get(
        "SAMPLES_DIR", Path(__file__).resolve().parents[1] / "samples")))
    event_log: Path | None = field(default_factory=lambda: Path(p) if (p := os.environ.get("EVENT_LOG")) else None)
    backlog_size: int = 2000
    ws_backlog: int = 300


class SubmitRequest(BaseModel):
    """A package submitted from the UI or API."""

    name: str = Field(min_length=1, max_length=200)
    files: dict[str, str] = Field(min_length=1)
    metadata: dict[str, float] | None = None


class UploadScanRequest(BaseModel):
    """Files uploaded from the browser: relative path (folder structure kept) -> source text."""

    root: str = Field(default="upload", max_length=200)
    files: dict[str, str] = Field(min_length=1)


def _clean_upload_path(raw: str) -> str | None:
    """Normalised relative path, or ``None`` if it is absolute or escapes the upload root."""
    norm = posixpath.normpath(raw.replace("\\", "/")).lstrip("/")
    if norm in ("", ".") or norm == ".." or norm.startswith("../") or ":" in norm.split("/", 1)[0]:
        return None
    return norm


def _file_verdict(report: dict[str, Any]) -> str:
    """Same mapping as scanner.py: blocked -> MALICIOUS, review -> SUSPICIOUS, otherwise BENIGN."""
    if not report["flagged"]:
        return "BENIGN"
    return "MALICIOUS" if report["severity"] in ("CRITICAL", "HIGH") else "SUSPICIOUS"


def _upload_file_result(path: str, group: str, size: int, report: dict[str, Any]) -> dict[str, Any]:
    verdict = _file_verdict(report)
    layers = report["layers"]
    nodes = [n for n in report.get("ast_risky_nodes", []) if n["severity"] in ("critical", "high") or verdict != "BENIGN"]
    return {
        "path": path, "group": group, "kind": "python", "size": size, "status": "analyzed", "verdict": verdict,
        "reason": None, "risk_score": report["risk_score"], "severity": report["severity"], "action": report["action"],
        "predicted_attack_type": report["predicted_attack_type"], "request_id": report.get("request_id"),
        "scores": {"ast_static": layers["ast_static"]["score"], "ast_verdict": layers["ast_static"]["verdict"],
                   "random_forest": layers["supervised"]["threat_probability"],
                   "isolation_forest": layers["anomaly"]["percentile"], "ast_influence": report["ast_influence"]["delta"]},
        "ast_risk_factors": [{"line": n["line"], "node": n["node"], "call": n["name"], "categories": n["categories"],
                              "severity": n["severity"], "import_time": n["module_level"]} for n in nodes[:10]],
        "astmaster_findings": [f for f in report.get("findings", []) if f["severity"] in ("critical", "high")][:8],
    }


class EventHub:
    """In-memory ring buffer + fan-out to WebSocket subscribers (+ optional JSONL persistence)."""

    def __init__(self, size: int, log_path: Path | None = None) -> None:
        self.events: deque[dict[str, Any]] = deque(maxlen=size)
        self.subscribers: set[asyncio.Queue[dict[str, Any]]] = set()
        self.total = 0
        self.log_path = log_path
        if log_path and log_path.exists():
            with log_path.open(encoding="utf-8") as fh:
                for line in fh:
                    with contextlib.suppress(json.JSONDecodeError):
                        self.events.append(json.loads(line))
                        self.total += 1

    def publish(self, events: list[dict[str, Any]]) -> None:
        """Append events to the ring buffer, fan out to WebSocket subscribers, and persist if configured."""
        for event in events:
            self.events.append(event)
            self.total += 1
            for q in list(self.subscribers):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:  # slow client: disconnect it rather than block everyone
                    self.subscribers.discard(q)
        if self.log_path:
            try:
                with self.log_path.open("a", encoding="utf-8") as fh:
                    fh.writelines(json.dumps(e, default=str) + "\n" for e in events)
            except OSError as exc:
                logger.warning("event log write failed: %s", exc)

    def recent(self, limit: int, request_id: str | None = None, type_prefix: str | None = None) -> list[dict[str, Any]]:
        """Most recent events, optionally filtered by request id and event-type prefix."""
        items = [e for e in self.events
                 if (request_id is None or e.get("request_id") == request_id)
                 and (type_prefix is None or str(e.get("type", "")).startswith(type_prefix))]
        return items[-limit:]


def _event(source: str, event_type: str, request_id: str | None = None, package: str | None = None,
           **data: Any) -> dict[str, Any]:
    return {"id": uuid.uuid4().hex, "ts": datetime.now(timezone.utc).isoformat(), "source": source,
            "type": event_type, "request_id": request_id, "package": package, "data": data}


def read_junit(path: Path) -> dict[str, Any]:
    """Summarise a pytest JUnit XML report (written by the tests container)."""
    if not path.exists():
        return {"available": False}
    root = ET.parse(path).getroot()
    suite = root if root.tag == "testsuite" else root.find("testsuite")
    if suite is None:
        return {"available": False}
    cases = []
    for case in suite.iter("testcase"):
        outcome = "passed"
        for tag in ("failure", "error", "skipped"):
            if case.find(tag) is not None:
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[tag]
        cases.append({"name": case.get("name"), "module": (case.get("classname") or "").split(".")[-1],
                      "outcome": outcome, "time": float(case.get("time") or 0)})
    counts = {k: int(suite.get(k, 0)) for k in ("tests", "failures", "errors", "skipped")}
    return {"available": True, **counts,
            "passed": counts["tests"] - counts["failures"] - counts["errors"] - counts["skipped"],
            "time": float(suite.get("time") or 0), "timestamp": suite.get("timestamp"), "cases": cases}


def load_samples(samples_dir: Path) -> dict[str, dict[str, Any]]:
    """Read bundled sample packages (``samples/<dir>/`` + optional ``package_meta.json``)."""
    samples: dict[str, dict[str, Any]] = {}
    if not samples_dir.is_dir():
        return samples
    for d in sorted(p for p in samples_dir.iterdir() if p.is_dir()):
        meta_path = d / "package_meta.json"
        meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
        files = {f.relative_to(d).as_posix(): f.read_text(encoding="utf-8", errors="replace")
                 for f in sorted(d.rglob("*")) if f.is_file() and not f.is_symlink()
                 and f.name != "package_meta.json" and f.suffix in _SAMPLE_SUFFIXES}
        name = meta.pop("name", d.name)
        samples[d.name] = {"name": name, "files": files, "metadata": meta}
    return samples


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory (tests create isolated instances)."""
    cfg = settings or Settings()
    hub = EventHub(cfg.backlog_size, cfg.event_log)
    app = FastAPI(title="Supply Chain Security — Admin Dashboard", version="1.0.0")
    app.state.hub = hub
    app.state.settings = cfg

    async def _get_json(client: httpx.AsyncClient, url: str) -> dict[str, Any]:
        try:
            resp = await client.get(url, timeout=5)
            body = resp.json()
            return {"reachable": True, "http_status": resp.status_code, **body}
        except Exception as exc:
            return {"reachable": False, "error": f"{type(exc).__name__}: {exc}"}

    async def _assess(name: str, files: dict[str, str], metadata: dict[str, Any] | None, via: str) -> dict[str, Any]:
        request_id = uuid.uuid4().hex
        hub.publish([_event("dashboard", "dashboard.submission", request_id, name, via=via, n_files=len(files))])
        payload = {"packages": [{"name": name, "files": files, "metadata": metadata or {}, "request_id": request_id}]}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{cfg.ai_engine_url}/assess", json=payload, timeout=120)
        except httpx.HTTPError as exc:
            raise HTTPException(502, f"AI engine unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, resp.json().get("error", "assessment failed"))
        return {"request_id": request_id, "report": resp.json()["reports"][0]}

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        """Serve the dashboard single-page UI."""
        return FileResponse(STATIC_DIR / "index.html")

    @app.post("/api/events")
    async def ingest(request: Request) -> dict[str, Any]:
        """Accept a batch of telemetry events from a service (requires the shared token)."""
        if cfg.event_token and not hmac.compare_digest(request.headers.get(TOKEN_HEADER, ""), cfg.event_token):
            raise HTTPException(401, "invalid event token")
        body = await request.json()
        events = body.get("events") if isinstance(body, dict) else None
        if not isinstance(events, list) or len(events) > MAX_EVENTS_PER_POST:
            raise HTTPException(400, f"'events' must be a list of at most {MAX_EVENTS_PER_POST}")
        clean = [e for e in events if isinstance(e, dict) and isinstance(e.get("type"), str)]
        hub.publish(clean)
        return {"accepted": len(clean)}

    @app.get("/api/events")
    async def events(limit: int = Query(200, ge=1, le=2000), request_id: str | None = None,
                     type: str | None = None) -> dict[str, Any]:  # noqa: A002
        """Return recent events, optionally filtered by ``request_id`` or ``type`` prefix."""
        return {"events": hub.recent(limit, request_id, type), "total": hub.total}

    @app.get("/api/health")
    async def health() -> dict[str, Any]:
        """Aggregate health of both services plus the training report and test-suite results."""
        async with httpx.AsyncClient() as client:
            ast, ai = await asyncio.gather(_get_json(client, f"{cfg.ast_service_url}/health"),
                                           _get_json(client, f"{cfg.ai_engine_url}/health"))
        ast.pop("feature_names", None)
        report_path = cfg.artifact_dir / "training_report.json"
        training = None
        if report_path.exists():
            rep = json.loads(report_path.read_text(encoding="utf-8"))
            training = {"layer_verification": rep.get("layer_verification"), "test_metrics": rep.get("test_metrics"),
                        "dataset": rep.get("dataset"), "top_features": rep.get("top_features"),
                        "training_seconds": rep.get("training_seconds")}
        return {"dashboard": {"events_total": hub.total, "ws_clients": len(hub.subscribers)},
                "ast_detection": ast, "ai_engine": ai, "training": training,
                "tests": read_junit(cfg.results_dir / "junit.xml")}

    app.state.upload_scan = None

    async def _assess_batch(client: httpx.AsyncClient, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        resp = await client.post(f"{cfg.ai_engine_url}/assess", json={"packages": packages}, timeout=300)
        if resp.status_code != 200:
            raise HTTPException(resp.status_code, resp.json().get("error", "assessment failed"))
        return resp.json()["reports"]

    @app.post("/api/scan/upload")
    async def scan_upload(req: UploadScanRequest) -> dict[str, Any]:
        """Scan uploaded Python files (single files or a whole folder) through AST + AI.

        Only ``.py`` files are accepted; anything else is listed under ``rejected``. Each file is
        scored on its own (like ``scanner.py``), so one bad file cannot affect the others.
        """
        started, started_at = time.perf_counter(), datetime.now(timezone.utc).isoformat()
        accepted: dict[str, str] = {}
        rejected: list[dict[str, str]] = []
        total = 0
        for raw, source in list(req.files.items())[:MAX_UPLOAD_FILES]:
            path = _clean_upload_path(raw)
            size = len(source.encode("utf-8", "surrogatepass"))
            if path is None:
                rejected.append({"path": raw, "reason": "unsafe path"})
            elif not path.lower().endswith(UPLOAD_SUFFIXES):
                rejected.append({"path": raw, "reason": "not a Python (.py) file"})
            elif size > MAX_UPLOAD_FILE_BYTES:
                rejected.append({"path": raw, "reason": "file larger than 2 MB"})
            elif total + size > MAX_UPLOAD_TOTAL_BYTES:
                rejected.append({"path": raw, "reason": "upload size budget (50 MB) exhausted"})
            else:
                accepted[path] = source
                total += size
        if len(req.files) > MAX_UPLOAD_FILES:
            rejected.append({"path": "...", "reason": f"only the first {MAX_UPLOAD_FILES} files are scanned"})
        if not accepted:
            raise HTTPException(400, {"error": "no Python (.py) files in the upload", "rejected": rejected[:50]})

        # Folder uploads keep their structure: the top-level folder is the project.
        multi_root = len({p.split("/", 1)[0] for p in accepted}) > 1 or any("/" not in p for p in accepted)
        items = []
        for path in sorted(accepted):
            group, _, inner = path.partition("/")
            if multi_root or not inner:
                group, inner = req.root or "upload", path
            items.append((path, group, inner))
        hub.publish([_event("dashboard", "scan.started", root=req.root, n_files=len(items), via="upload")])

        results: list[dict[str, Any]] = []
        async with httpx.AsyncClient() as client:
            for start in range(0, len(items), UPLOAD_BATCH):
                batch = items[start:start + UPLOAD_BATCH]
                pkgs = [{"name": group, "files": {inner: accepted[path]}, "request_id": f"upl-{uuid.uuid4().hex[:12]}"}
                        for path, group, inner in batch]
                try:
                    reports = await _assess_batch(client, pkgs)
                    pairs = list(zip(batch, reports))
                except (HTTPException, httpx.HTTPError):
                    pairs = []
                    for item, pkg in zip(batch, pkgs):  # isolate the failing file
                        try:
                            pairs.append((item, (await _assess_batch(client, [pkg]))[0]))
                        except (HTTPException, httpx.HTTPError) as exc:
                            detail = exc.detail if isinstance(exc, HTTPException) else str(exc)
                            results.append({"path": item[0], "group": item[1], "kind": "python",
                                            "size": len(accepted[item[0]]), "status": "error", "verdict": "ERROR",
                                            "reason": str(detail)[:200], "risk_score": None, "scores": {},
                                            "ast_risk_factors": [], "astmaster_findings": []})
                for (path, group, _), rep in pairs:
                    results.append(_upload_file_result(path, group, len(accepted[path]), rep))

        verdicts = Counter(r["verdict"] for r in results)
        groups = []
        for g in sorted({r["group"] for r in results}):
            gr = [r for r in results if r["group"] == g]
            scored = [r["risk_score"] for r in gr if r["risk_score"] is not None]
            groups.append({"group": g, "package_name": g, "files_total": len(gr), "files_analyzed": len(scored),
                           "verdicts": dict(Counter(r["verdict"] for r in gr)), "max_risk": max(scored, default=None),
                           "project_verdict": min((r["verdict"] for r in gr), key=_VERDICT_ORDER.__getitem__),
                           "flagged_files": [r["path"] for r in gr if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")]})
        report = {
            "scan_id": uuid.uuid4().hex, "root": f"upload: {req.root}", "started_at": started_at,
            "duration_seconds": round(time.perf_counter() - started, 2),
            "engine": {"mode": "dashboard upload", "ai_engine": cfg.ai_engine_url},
            "summary": {"files_discovered": len(req.files), "files_analyzed": sum(r["status"] == "analyzed" for r in results),
                        "by_kind": {"python": len(accepted), "rejected": len(rejected)}, "verdicts": dict(verdicts),
                        "overall_verdict": "MALICIOUS" if verdicts["MALICIOUS"] else
                        "SUSPICIOUS" if verdicts["SUSPICIOUS"] else "CLEAN"},
            "groups": groups, "files": sorted(results, key=lambda r: r["path"]), "rejected": rejected,
        }
        app.state.upload_scan = report
        hub.publish([_event("dashboard", "scan.completed", root=report["root"], summary=report["summary"],
                            groups=groups, flagged=[r for r in results if r["verdict"] in ("MALICIOUS", "SUSPICIOUS")])])
        return report

    @app.get("/api/scans/latest")
    async def latest_scan(full: bool = False) -> dict[str, Any]:
        """Latest scan (``scanner.py`` report on disk or dashboard upload, whichever is newer)."""
        candidates = []
        path = cfg.reports_dir / "scan_report.json"
        if path.exists():
            candidates.append(json.loads(path.read_text(encoding="utf-8")))
        if app.state.upload_scan is not None:
            candidates.append(json.loads(json.dumps(app.state.upload_scan)))
        if not candidates:
            return {"available": False}
        report = max(candidates, key=lambda r: r["started_at"])
        files = report.pop("files")
        report["flagged"] = [f for f in files if f["verdict"] in ("MALICIOUS", "SUSPICIOUS", "ERROR")]
        if full:
            report["files"] = files
        return {"available": True, **report}

    @app.post("/api/submit")
    async def submit(req: SubmitRequest) -> dict[str, Any]:
        """Submit a custom package for assessment through the AI engine."""
        if len(req.files) > MAX_SUBMIT_FILES or sum(len(v) for v in req.files.values()) > MAX_SUBMIT_BYTES:
            raise HTTPException(413, "package too large")
        return await _assess(req.name, req.files, req.metadata, via="api")

    @app.get("/api/samples")
    async def samples() -> dict[str, Any]:
        """List the bundled mock sample packages."""
        return {"samples": [{"id": k, "name": v["name"], "files": sorted(v["files"])}
                            for k, v in load_samples(cfg.samples_dir).items()]}

    @app.post("/api/samples/{sample_id}")
    async def submit_sample(sample_id: str) -> dict[str, Any]:
        """Submit one bundled sample package for assessment."""
        sample = load_samples(cfg.samples_dir).get(sample_id)
        if sample is None:
            raise HTTPException(404, "unknown sample")
        return await _assess(sample["name"], sample["files"], sample["metadata"], via="sample")

    @app.websocket("/ws")
    async def ws(socket: WebSocket) -> None:
        """Stream the event backlog, then every new event, to a connected browser."""
        await socket.accept()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=2000)
        hub.subscribers.add(queue)
        try:
            await socket.send_json({"kind": "backlog", "events": hub.recent(cfg.ws_backlog)})
            while True:
                event = await queue.get()
                await socket.send_json({"kind": "event", "event": event})
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            hub.subscribers.discard(queue)

    @app.exception_handler(json.JSONDecodeError)
    async def bad_json(_: Request, exc: json.JSONDecodeError) -> JSONResponse:
        """Return 400 (not 500) for malformed JSON bodies."""
        return JSONResponse({"detail": f"invalid JSON: {exc.msg}"}, status_code=400)

    return app


app = create_app()


def main() -> None:
    """Run with uvicorn (``python -m dashboard.app``)."""
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    uvicorn.run(app, host=os.environ.get("DASHBOARD_HOST", "127.0.0.1"),
                port=int(os.environ.get("DASHBOARD_PORT", 8501)), log_level="info")


if __name__ == "__main__":
    main()
