"""Small HTTP interface built only on the standard library."""

from __future__ import annotations

import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import threading
import time
import zipfile
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlsplit

from .dashboard import content_security_policy, render_dashboard
from .db import (
    AnalysisRecord, AnalysisRepository, Database, ScanRepository, ScanRunning, SignalCache, SignatureRepository, TaskRepository,
)
from .discovery import TreeScanner, iter_tree, list_dir
from .executor import LocalExecutor, UnknownTemplate
from .models import Severity
from .pipeline import analyze_source
from .secscan import Item, SecurityScanner, clean_upload_path, items_from_zip, strip_common_root
from .security import SEVERITIES

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_FOLDER_BYTES = 200 * 1024 * 1024
MAX_API_BYTES = 64 * 1024 * 1024
FLUSH_EVERY = 512
MAX_WAIT_SECONDS = 30.0

# Folder uploads need a little script: browsers only expose relative paths to it.
_UPLOAD_SCRIPT = """<script>
async function sendFiles(pairs, field) {
  document.getElementById('status').textContent = 'Scanning ' + pairs.length + ' file(s)...';
  const body = new FormData();
  for (const [file, path] of pairs) body.append(field, file, path);
  const reply = await fetch(field === 'example_file' ? '/upload' : '/upload-folder', {method: 'POST', body});
  if (reply.ok) location = reply.url;
  else document.getElementById('status').textContent = 'Upload failed: ' + await reply.text();
}
function readBatch(reader) {
  return new Promise((done, fail) => reader.readEntries(done, fail));
}
async function walk(entry, path, out) {
  if (entry.isFile) {
    out.push([await new Promise((done, fail) => entry.file(done, fail)), path + entry.name]);
    return;
  }
  const reader = entry.createReader();
  for (let batch = await readBatch(reader); batch.length; batch = await readBatch(reader))
    for (const child of batch) await walk(child, path + entry.name + '/', out);
}
function sendFolderInput(event) {
  event.preventDefault();
  const files = [...event.target.elements.folder.files];
  if (files.length) sendFiles(files.map(f => [f, f.webkitRelativePath || f.name]), 'files');
}
addEventListener('dragover', e => e.preventDefault());
addEventListener('drop', async e => {
  e.preventDefault();
  const entries = [...e.dataTransfer.items].map(i => i.webkitGetAsEntry()).filter(Boolean);
  const out = [];
  for (const entry of entries) await walk(entry, '', out);
  if (!out.length) return;
  if (out.length === 1 && entries[0].isFile) {
    const name = out[0][1].toLowerCase();
    sendFiles(out, name.endsWith('.zip') ? 'archive' : 'files');
  } else sendFiles(out, 'files');
});
</script>"""


def _upload_name(paths: list[str]) -> str:
    """The folder's name, the file's name, or a count for loose files."""
    if len(paths) == 1:
        return paths[0].rpartition("/")[2]
    tops = {path.partition("/")[0] for path in paths}
    if len(tops) == 1 and all("/" in path for path in paths):
        return tops.pop()
    return f"{len(paths)} uploaded files"


def parse_multipart(content_type: str, body: bytes) -> list[tuple[str, str | None, bytes]]:
    """Return (field, filename, data) per part. Much faster than email.parser for big folders."""
    match = re.search(r'boundary="?([^";,\s]+)"?', content_type, re.I)
    if not match:
        return []
    delimiter = b"--" + match.group(1).encode("latin-1", "replace")
    parts = []
    for chunk in body.split(delimiter)[1:]:
        if chunk.startswith(b"--"):
            break
        head, separator, data = chunk.partition(b"\r\n\r\n")
        if not separator:
            continue
        if data.endswith(b"\r\n"):
            data = data[:-2]
        header = head.decode("utf-8", "replace")
        name = re.search(r'[\s;]name="([^"]*)"', header)
        filename = re.search(r'filename="([^"]*)"', header)
        if name:
            parts.append((name.group(1), filename.group(1) if filename else None, data))
    return parts


def esc(value: object) -> str:
    return html.escape(str(value))


def url_arg(path: str) -> str:
    return quote(path, safe="/", errors="surrogateescape")


def page_head(title: str) -> str:
    return f"<!doctype html><html><head><meta charset=utf-8><title>{esc(title)}</title></head><body>"


def red(html_text: str) -> str:
    """Red without CSS. The caller must pass text that's already escaped."""
    return f'<font color="red">{html_text}</font>'


def table(headers: list[str], rows: list[list[object]]) -> str:
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{esc(c)}</td>" for c in row) + "</tr>" for row in rows)
    return f"<table border=1><tr>{head}</tr>{body}</table>"


@dataclass(slots=True)
class App:
    root: Path
    database: Database
    analyses: AnalysisRepository
    scans: ScanRepository
    security: SecurityScanner
    executor: LocalExecutor | None = None
    token: str = ""
    loopback_only: bool = True
    scanner: TreeScanner = field(default_factory=TreeScanner)


class PathDenied(Exception):
    pass


class Handler(BaseHTTPRequestHandler):
    server_version = "ASTMaster"
    sys_version = ""
    timeout = 120
    disable_nagle_algorithm = True

    @property
    def app(self) -> App:
        return self.server.app

    def log_message(self, format: str, *args: object) -> None:
        pass  # A log line per request would slow the Pi and add nothing here.

    # ---- Dispatch ---------------------------------------------------------

    def _host_allowed(self) -> bool:
        """Reject DNS-rebinding attacks while we serve only the local machine."""
        if not self.app.loopback_only:
            return True
        host = urlsplit("//" + self.headers.get("Host", "")).hostname or ""
        return host in ("localhost", "127.0.0.1", "::1")

    def _dispatch(self, routes: dict) -> None:
        try:
            if not self._host_allowed():
                self._send_text(403, "Forbidden host\n")
                return
            parts = urlsplit(self.path)
            query = parse_qs(parts.query, errors="surrogateescape")
            path = parts.path
            if self.command == "DELETE":
                self._remove(path)
            elif path.startswith("/api/tasks"):
                self._api(path, query)
            elif path.startswith("/result/"):
                self._result(path)
            elif path.startswith("/report/"):
                self._report(path.removeprefix("/report/"))
            elif path in routes:
                routes[path](query)
            else:
                self._send_text(404, "Not found\n")
        except PathDenied as error:
            self._send_text(403, f"{error}\n")
        except (BrokenPipeError, ConnectionResetError):
            pass  # The browser went away; nothing left to do.

    def do_GET(self) -> None:
        self._dispatch({
            "/": lambda q: self._browse(""),
            "/browse": lambda q: self._browse(self._arg(q, "path"), self._arg(q, "recursive") == "1"),
            "/analyze": lambda q: self._analyze_path(self._arg(q, "path")),
            "/scan": lambda q: self._scan(self._arg(q, "path")),
            "/security": lambda q: self._security_scan(self._arg(q, "path")),
            "/reports": lambda q: self._reports(),
            "/dashboard": lambda q: self._dashboard(),
            "/api/dashboard": lambda q: self._dashboard_data(),
        })

    def do_POST(self) -> None:
        self._dispatch({"/upload": lambda q: self._upload(), "/upload-folder": lambda q: self._upload_folder()})

    def do_DELETE(self) -> None:
        self._dispatch({})

    @staticmethod
    def _arg(query: dict[str, list[str]], name: str) -> str:
        return query.get(name, [""])[0]

    # ---- Responses --------------------------------------------------------

    def _send(self, status: int, body: bytes, content_type: str, headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8", "replace"), "text/plain; charset=utf-8")

    def _send_html(self, text: str, status: int = 200) -> None:
        self._send(status, text.encode("utf-8", "replace"), "text/html; charset=utf-8")

    def _send_json(self, status: int, value: dict) -> None:
        self._send(status, json.dumps(value).encode("ascii"), "application/json")

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _start_stream(self) -> None:
        """Send headers now, so the page starts to render before listing finishes."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.close_connection = True
        self.end_headers()

    def _write(self, text: str) -> None:
        self.wfile.write(text.encode("utf-8", "replace"))

    # ---- Paths ------------------------------------------------------------

    def _resolve(self, relative: str) -> Path:
        """Resolve a user path, following symlinks, and confine it to the root."""
        try:
            resolved = (self.app.root / relative).resolve()
        except (ValueError, OSError, RuntimeError) as error:
            raise PathDenied("Invalid path") from error
        if not resolved.is_relative_to(self.app.root):
            raise PathDenied("Path is outside the target directory")
        return resolved

    def _relative(self, path: str) -> str:
        return os.path.relpath(path, self.app.root)

    # ---- Explorer ---------------------------------------------------------

    def _entry_line(self, entry: os.DirEntry, relative: str) -> str:
        link = url_arg(relative)
        label = esc(relative)
        if entry.is_symlink():
            return f"<li>{label} (link)</li>"
        if entry.is_dir(follow_symlinks=False):
            return f'<li><a href="/browse?path={link}">{label}/</a></li>'
        if entry.name.endswith(".py"):
            return f'<li>{label} [<a href="/analyze?path={link}">analyze</a>]</li>'
        return f"<li>{label}</li>"

    def _browse(self, relative: str, recursive: bool = False) -> None:
        directory = self._resolve(relative)
        if not directory.is_dir():
            self._send_text(404, "Not a directory\n")
            return
        started = time.perf_counter()
        display = "." if directory == self.app.root else self._relative(str(directory))
        link = url_arg("" if display == "." else display)

        entries = None
        if not recursive:
            try:
                entries = list_dir(str(directory))
            except OSError as error:
                self._send_text(403, f"Can't read directory: {error.strerror}\n")
                return

        self._start_stream()
        head = [
            page_head(f"AST Master: {display}"),
            "<h1>AST Master</h1>",
            '<h2>Upload</h2><p id=status>Drop a file, folder or .zip anywhere on this page, or choose one:</p>',
            '<form method=post action=/upload-folder enctype=multipart/form-data>',
            "Python file(s): <input type=file name=files accept=.py multiple required> ",
            "<input type=submit value='Security scan'></form>",
            '<form onsubmit="sendFolderInput(event)">',
            "Code folder: <input type=file name=folder webkitdirectory multiple required> ",
            "<input type=submit value='Security scan'></form>",
            '<form method=post action=/upload-folder enctype=multipart/form-data>',
            "Zip of a folder: <input type=file name=archive accept=.zip required> ",
            "<input type=submit value='Security scan'></form>",
            '<form method=post action=/upload enctype=multipart/form-data>',
            "Python file, for thread analysis: <input type=file name=example_file accept=.py required> ",
            "<input type=submit value=Analyze></form>",
            _UPLOAD_SCRIPT,
            '<p><a href="/dashboard">Live dashboard</a> | <a href="/reports">Security reports</a></p>',
            f"<h2>Files in {esc(display)}</h2><p>",
        ]
        if display != ".":
            parent = os.path.dirname(display)
            head.append(f'<a href="/browse?path={url_arg(parent)}">Up</a> | ')
        if recursive:
            head.append(f'<a href="/browse?path={link}">This folder only</a>')
        else:
            head.append(f'<a href="/browse?path={link}&recursive=1">All subfolders</a>')
        head.append(f' | <a href="/security?path={link}">Security scan</a>')
        head.append(f' | <a href="/scan?path={link}">Thread scan</a></p><ul>')
        self._write("".join(head))

        count = 0
        batch: list[str] = []
        errors: list[str] = []
        if recursive:
            source = iter_tree(
                str(directory), on_error=lambda e: errors.append(f"{e.filename}: {e.strerror}"), sort=True
            )
        else:
            source = iter(entries)
        for entry in source:
            count += 1
            batch.append(self._entry_line(entry, self._relative(entry.path)))
            if len(batch) >= FLUSH_EVERY:
                self._write("".join(batch))
                batch.clear()
        batch.append("</ul>")
        for message in errors:
            batch.append(f"<p>Couldn't read {esc(message)}</p>")
        elapsed = (time.perf_counter() - started) * 1000
        batch.append(f"<p>{count} entries in {elapsed:.1f} ms</p></body></html>")
        self._write("".join(batch))

    def _scan(self, relative: str) -> None:
        directory = self._resolve(relative)
        if not directory.is_dir():
            self._send_text(404, "Not a directory\n")
            return
        tree = self.app.scanner.scan(str(directory), threads_only=True)
        stats = tree.stats
        rows = []
        for report in tree.reports:
            if not report.has_threads and not report.issues:
                continue
            path = self._relative(report.path)
            link = f'<a href="/analyze?path={url_arg(path)}">{esc(path)}</a>'
            errors = sum(i.severity is Severity.ERROR for i in report.issues)
            warnings = sum(i.severity is Severity.WARNING for i in report.issues)
            verdict = "suitable" if report.feasible else "not suitable"
            threads = len(report.scan.threads) if report.scan else 0
            rows.append(
                f"<tr><td>{link}</td><td>{verdict}</td><td>{threads}</td>"
                f"<td>{report.template_count}</td><td>{errors}</td><td>{warnings}</td></tr>"
            )
        self._send_html(
            page_head("Scan")
            + f'<p><a href="/browse?path={url_arg(relative)}">Back</a></p><h1>Thread scan: {esc(relative or ".")}</h1>'
            + f"<p>{stats.files} Python files in {stats.seconds * 1000:.0f} ms: {stats.parsed} parsed, "
            + f"{stats.skipped_no_thread} had no threads, {stats.cache_hits} unchanged since last scan, "
            + f"{stats.skipped_too_large} too large, {stats.failed} unreadable.</p>"
            + "<table border=1><tr><th>File</th><th>Verdict</th><th>Threads</th><th>Templates</th>"
            + "<th>Errors</th><th>Warnings</th></tr>"
            + "".join(rows) + "</table></body></html>"
        )

    # ---- Analysis ---------------------------------------------------------

    def _analyze_path(self, relative: str) -> None:
        path = self._resolve(relative)
        if not path.is_file():
            self._send_text(404, "Not a file\n")
            return
        if path.stat().st_size > MAX_UPLOAD_BYTES:
            self._send_text(413, "File too large\n")
            return
        try:
            data = path.read_bytes()
        except OSError as error:
            self._send_text(403, f"Can't read file: {error.strerror}\n")
            return
        record = self.app.analyses.save(relative, analyze_source(data, relative))
        self._redirect(f"/result/{record.record_id}")

    def _read_body(self, limit: int) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self._send_text(411, "Content-Length required\n")
            self.close_connection = True
            return None
        if length < 0 or length > limit:
            self._send_text(413, "Request too large\n")
            self.close_connection = True
            return None
        return self.rfile.read(length)

    def _upload(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            self._send_text(415, "Expected a multipart form upload\n")
            return
        body = self._read_body(MAX_UPLOAD_BYTES)
        if body is None:
            return
        for field_name, filename, data in parse_multipart(content_type, body):
            if field_name == "example_file":
                # The name is only a label: it's escaped on output, never used as a path.
                label = clean_upload_path(filename or "") or "upload.py"
                record = self.app.analyses.save(label, analyze_source(data, label))
                self._redirect(f"/result/{record.record_id}")
                return
        self._send_text(400, "No example_file field in the upload\n")

    def _upload_folder(self) -> None:
        content_type = self.headers.get("Content-Type", "")
        if not content_type.lower().startswith("multipart/form-data"):
            self._send_text(415, "Expected a multipart form upload\n")
            return
        body = self._read_body(MAX_FOLDER_BYTES)
        if body is None:
            return
        items: list[Item] = []
        name = "upload"
        for field_name, filename, data in parse_multipart(content_type, body):
            path = clean_upload_path(filename or "")
            if field_name == "archive" and data:
                name = path or "archive.zip"
                try:
                    items.extend(items_from_zip(data))
                except zipfile.BadZipFile:
                    self._send_text(400, "That file isn't a valid zip archive\n")
                    return
            elif field_name == "files" and path:
                items.append(Item(path, data=data, size=len(data)))
        if not items:
            self._send_text(400, "No files in the upload\n")
            return
        if name == "upload":
            name = _upload_name([item.path for item in items])
        strip_common_root(items)
        report = self.app.security.scan_items(items, name, "upload")
        self._redirect(f"/report/{report.scan_id}")

    def _security_scan(self, relative: str) -> None:
        directory = self._resolve(relative)
        if not directory.is_dir():
            self._send_text(404, "Not a directory\n")
            return
        report = self.app.security.scan_directory(str(directory), relative or directory.name)
        self._redirect(f"/report/{report.scan_id}")

    def _report(self, scan_id: str) -> None:
        report = self.app.scans.get(scan_id)
        if report is None:
            self._send_text(404, "Unknown report\n")
        else:
            self._send_html(render_report(report))

    def _dashboard(self) -> None:
        nonce = secrets.token_urlsafe(16)
        self._send(
            200, render_dashboard(nonce, MAX_FOLDER_BYTES).encode("utf-8"), "text/html; charset=utf-8",
            {"Content-Security-Policy": content_security_policy(nonce), "Cache-Control": "no-store",
             "X-Content-Type-Options": "nosniff"},
        )

    def _dashboard_data(self) -> None:
        self._send(
            200, json.dumps(self.app.scans.dashboard()).encode("ascii"), "application/json",
            {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
        )

    def _remove(self, path: str) -> None:
        """Delete rows for the dashboard's Remove buttons.

        DELETE means another website's page can't send this without the browser first asking
        permission, which this server never gives. The Origin check is a second lock on that.
        """
        if not self.app.loopback_only:
            self._send_text(403, "Removing is only available when the server accepts connections from this machine only\n")
            return
        origin = self.headers.get("Origin")
        if origin is not None and urlsplit(origin).netloc != self.headers.get("Host"):
            self._send_text(403, "Forbidden origin\n")
            return
        kind, _, identifier = path.removeprefix("/api/").partition("/")
        try:
            if kind == "payloads" and identifier.isascii() and identifier.isdigit():
                removed = self.app.scans.remove_payload(int(identifier))
            elif kind == "scans" and identifier:
                removed = self.app.scans.remove_scan(identifier)
            elif kind == "repositories" and identifier.isascii() and identifier.isdigit():
                removed = self.app.scans.remove_repository(int(identifier))
            else:
                self._send_text(404, "Not found\n")
                return
        except ScanRunning:
            self._send_text(409, "That scan is still running. Try again when it finishes.\n")
            return
        except OverflowError:
            removed = False
        if removed:
            self._send_json(200, {"removed": True})
        else:
            self._send_text(404, "It has already been removed.\n")

    def _reports(self) -> None:
        rows = "".join(
            f'<tr><td><a href="/report/{esc(r["scan_id"])}">{esc(r["name"])}</a></td><td>{esc(r["verdict"])}, risk {_risk_label(r["risk_score"])}</td>'
            f'<td>{esc(r["source"])}</td><td>{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["created_at"]))}</td></tr>'
            for r in self.app.scans.recent()
        )
        self._send_html(
            page_head("Security reports") + '<p><a href="/">Back</a> | <a href="/dashboard">Live dashboard</a></p><h1>Security reports</h1>'
            "<table border=1><tr><th>Name</th><th>Verdict</th><th>Source</th><th>Time</th></tr>"
            f"{rows}</table></body></html>"
        )

    def _result(self, path: str) -> None:
        _, _, rest = path.partition("/result/")
        record_id, _, suffix = rest.partition("/")
        record = self.app.analyses.get(record_id)
        if record is None:
            self._send_text(404, "Unknown or expired result\n")
        elif suffix == "transformed.py" and record.transformed_source:
            self._send(200, record.transformed_source.encode("utf-8", "surrogatepass"), "text/plain; charset=utf-8")
        elif suffix:
            self._send_text(404, "Not found\n")
        else:
            self._send_html(render_result(record))

    # ---- Task API ---------------------------------------------------------

    def _api(self, path: str, query: dict[str, list[str]]) -> None:
        executor = self.app.executor
        if executor is None:
            self._send_json(503, {"error": "execution is off: start the server with --enable-execution"})
            return
        supplied = self.headers.get("X-Mediator-Token", "").encode("utf-8", "replace")
        if not hmac.compare_digest(supplied, self.app.token.encode()):
            self._send_json(401, {"error": "missing or wrong X-Mediator-Token"})
            return
        if path == "/api/tasks" and self.command == "POST":
            self._api_submit(executor)
        elif path.startswith("/api/tasks/") and self.command == "GET":
            self._api_status(executor, path.removeprefix("/api/tasks/"), query)
        else:
            self._send_json(404, {"error": "not found"})

    def _api_submit(self, executor: LocalExecutor) -> None:
        body = self._read_body(MAX_API_BYTES)
        if body is None:
            return
        try:
            request = json.loads(body)
            task_id = executor.submit(request["template_id"], request["args_repr"], request["kwargs_repr"])
        except UnknownTemplate:
            self._send_json(404, {"error": "unknown template: upload the file again"})
        except (ValueError, TypeError, KeyError) as error:
            self._send_json(400, {"error": f"bad task request: {error}"})
        else:
            self._send_json(201, {"task_id": task_id})

    def _api_status(self, executor: LocalExecutor, task_id: str, query: dict[str, list[str]]) -> None:
        try:
            wait = min(MAX_WAIT_SECONDS, max(0.0, float(self._arg(query, "wait") or 0)))
        except ValueError:
            wait = 0.0
        reply = executor.status(task_id, wait)
        if reply is None:
            self._send_json(404, {"error": "unknown task"})
        else:
            self._send_json(200, reply)


_VERDICTS = {
    "SAFE": "SAFE: no supply chain attack indicators found.",
    "SUSPICIOUS": "SUSPICIOUS: review these findings before trusting this code.",
    "MALICIOUS": "MALICIOUS: this contains supply chain attack indicators. Do not install or run it.",
}


def _risk_label(score: int | None) -> str:
    return "not scored" if score is None else f"{score}/100"


def render_report(report: dict) -> str:
    stats = report["stats"]
    findings = report["findings"]
    out = [page_head(f"Security report: {report['name']}"), '<p><a href="/reports">All reports</a> | <a href="/">Home</a></p>']
    out.append(f"<h1>Security report: {esc(report['name'])}</h1>")
    verdict = esc(_VERDICTS[report["verdict"]])
    out.append(f"<h2>{verdict if report['verdict'] == 'SAFE' else red(verdict)}</h2>")
    out.append(f"<p>Risk score: {_risk_label(report['risk_score'])}. It ranks results for review and isn't a probability.</p>")
    if report["removed_alerts"]:
        out.append(
            f"<p><b>{report['removed_alerts']} alert(s) were removed from this report.</b> "
            "The verdict and risk score are from the original scan.</p>"
        )
    if report["verdict"] == "SAFE":
        out.append(
            "<p>This is static analysis: it found nothing known to be dangerous, which isn't proof "
            "the code is safe. It can't see behaviour that only appears at runtime.</p>"
        )
    phase1, phase2, phase3 = stats["phase1"], stats["phase2"], stats["phase3"]
    out.append(f"<p>{stats['scanned']} files in {stats['seconds'] * 1000:.0f} ms. Nothing was executed.</p>")
    out.append(table(
        ["Phase", "Result", "Time"],
        [
            ["1. Text filter", f"{phase1['python_files']} Python files: {phase1['cleared']} cleared, "
             f"{phase1['flagged']} flagged, {phase1['entry_points']} entry points", f"{phase1['seconds'] * 1000:.1f} ms"],
            ["2. AST analysis", f"{phase2['python_files']} Python and {phase2['other_files']} packaging or script files "
             f"({stats['cache_hits']} already known from their content hash)", f"{phase2['seconds'] * 1000:.1f} ms"],
            ["3. Clustering", f"{phase3['status']}: {phase3['vectors']} compared, {phase3['matches']} matched a known attack",
             f"{phase3['seconds'] * 1000:.1f} ms"],
        ],
    ))
    if stats["not_scanned"]:
        out.append(f"<p>{red(str(stats['not_scanned']))} item(s) couldn't be fully analyzed: see below.</p>")
    counts = {level: sum(f.severity == level for f in findings) for level in reversed(SEVERITIES)}
    out.append("<p>" + ", ".join(f"{count} {level}" for level, count in counts.items()) + "</p>")

    serious = [f for f in findings if f.severity != "low"]
    if serious:
        out.append("<h2>Findings</h2>")
        out.append(_findings_table(serious))
    low = [f for f in findings if f.severity == "low"]
    if low:
        out.append(f"<details><summary>{len(low)} low severity notes</summary>{_findings_table(low)}</details>")

    candidates = [f for f in report["files"] if f["thread_count"]]
    if candidates:
        out.append("<h2>Parallel execution candidates</h2>")
        out.append(table(
            ["File", "Threads", "Parallel"],
            [[f["path"], f["thread_count"], "suitable" if f["parallel_feasible"] else "not suitable"] for f in candidates],
        ))
    flagged = [f for f in report["files"] if f["phase1"] == "flagged"]
    out.append(f"<details><summary>{len(flagged)} files flagged by the text filter</summary><ul>")
    out.extend(f"<li>{red(esc(f['path']))}: {esc(f['phase1_reasons'])}</li>" for f in flagged)
    out.append("</ul></details>")
    out.append(f"<details><summary>{len(report['files'])} files checked</summary>")
    out.append(table(
        ["File", "Size", "Phase 1", "Status", "Functions", "Loops", "Worst severity", "SHA-256"],
        [[f["path"], f["size"], f["phase1"], f["status"], f["functions"], f["loops"], f["worst_severity"] or "", f["sha256"] or ""]
         for f in report["files"]],
    ))
    out.append("</details></body></html>")
    return "".join(out)


def _findings_table(findings: list) -> str:
    return table(
        ["Severity", "When it runs", "Location", "Rule", "What it means", "Detail", "Code"],
        [[f.severity, f.context, f"{f.path}:{f.line}" if f.line else f.path, f.rule, f.message, f.detail, f.snippet]
         for f in findings],
    )


def render_result(record: AnalysisRecord) -> str:
    result = record.result
    scan = result.scan
    out = [page_head(f"Analysis: {record.filename}"), '<p><a href="/">Back</a></p>']
    out.append(f"<h1>{esc(record.filename)}</h1>")
    if result.feasible:
        out.append(f"<p><b>Suitable for parallel execution</b>: {len(result.templates)} template(s).</p>")
    else:
        out.append("<p><b>Not suitable for parallel execution</b>: no templates produced.</p>")

    if result.issues:
        out.append("<h2>Alerts</h2>")
        out.append(table(
            ["Severity", "Line", "Code", "Message"],
            [[i.severity.value, i.lineno or "", i.code, i.message] for i in result.issues],
        ))
    out.append("<h2>Functions</h2>")
    out.append(table(
        ["Name", "Lines", "Calls from main", "Thread targets from main", "Type", "Calls in this file"],
        [[f.qualname, f"{f.lineno}-{f.end_lineno}", f.calls_from_main, f.thread_starts_from_main,
          f.classification, ", ".join(f.user_calls)] for f in scan.functions],
    ))
    out.append("<h2>Loops</h2>")
    out.append(table(
        ["Type", "Lines", "Function", "Nested", "Inner loops", "Calls", "Loop vars", "Assigned", "Local reads"],
        [[l.loop_type, f"{l.lineno}-{l.end_lineno}", l.parent_function or "", "yes" if l.is_nested else "no",
          ", ".join(map(str, l.inner_loop_lines)), ", ".join(l.function_calls), ", ".join(l.loop_vars),
          ", ".join(l.assigned_vars), ", ".join(l.read_vars)] for l in scan.loops],
    ))
    out.append("<h2>Threads</h2>")
    out.append(table(
        ["Variable", "Target", "Args", "Kwargs", "Line", "Function", "Loop", "start()", "join()"],
        [[t.var_name or "", t.target or "", ", ".join(t.args), t.kwargs or "", t.lineno, t.parent_function or "",
          t.loop_type or "", ", ".join(map(str, t.start_lines)), ", ".join(map(str, t.join_lines))]
         for t in scan.threads],
    ))
    if result.templates:
        out.append("<h2>Templates</h2>")
        for template in result.templates:
            kind = "reused per loop iteration" if template.is_loop_template else "single use"
            out.append(f"<h3>{esc(template.target)} ({esc(template.template_id)}, {kind})</h3>")
            out.append(f"<pre>{esc(template.source)}</pre>")
    if record.transformed_source:
        out.append("<h2>Transformed program</h2>")
        out.append(f'<p><a href="/result/{esc(record.record_id)}/transformed.py">Open as plain text</a></p>')
        out.append(f"<pre>{esc(record.transformed_source)}</pre>")
    out.append("</body></html>")
    return "".join(out)


def create_server(
    root: str | Path,
    host: str = "127.0.0.1",
    port: int = 8000,
    enable_execution: bool = False,
    token: str | None = None,
    db_path: str | Path | None = None,
    local_only: bool = False,
) -> ThreadingHTTPServer:
    database = Database(db_path)
    analyses = AnalysisRepository(database)
    tasks = TaskRepository(database)
    scans = ScanRepository(database)
    tasks.fail_interrupted()
    scans.fail_interrupted()
    security = SecurityScanner(SignalCache(database), scans, SignatureRepository(database))
    # sklearn takes a moment to import, so don't make the first report wait for it.
    threading.Thread(target=security.warm_up, daemon=True).start()
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host == "localhost"
    server = ThreadingHTTPServer((host, port), Handler)
    server.app = App(
        root=Path(root).resolve(),
        database=database,
        analyses=analyses,
        scans=scans,
        security=security,
        executor=LocalExecutor(analyses, tasks) if enable_execution else None,
        token=token or secrets.token_urlsafe(24),
        loopback_only=loopback or local_only,
    )
    return server
