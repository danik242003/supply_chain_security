#!/usr/bin/env python3
"""Recursive supply chain scanner: every relevant file in a directory tree -> AST -> AI -> audit report.

Pipeline per scan::

    discover (recursive walk + in-memory archive members)
      -> classify (python / install manifest / script / archive / binary / skipped)
      -> AST static analysis (ast_detection: AST Master + built-in node visitors)
      -> Random Forest + Isolation Forest + hybrid score (ai_engine)
      -> per-file verdicts, per-project roll-up, JSON + CLI report

Two execution modes:

* ``service`` (default when ``AI_ENGINE_URL`` is set, e.g. the ``scanner`` container):
  files go to the running ``ai_engine`` container, which calls ``ast_detection``.
  Every file also streams live to the dashboard.
* ``local``: the AST analyzer and the trained ``.joblib`` models run in-process.

Robustness: files are scored in batches; if a batch fails, it is retried file by file so one
malformed file cannot sink the scan. Unparseable source is still analysed (AST Master scans
the raw text of files Python cannot parse). Nothing is ever executed, imported or extracted
to disk.

Usage::

    python scanner.py ../supply_chain_lab                     # local mode, CLI summary
    python scanner.py ../supply_chain_lab -o report.json --all
    AI_ENGINE_URL=http://ai_engine:8100 python scanner.py /lab   # service mode
    docker compose run --rm scanner                           # scan ../supply_chain_lab in Docker
"""

from __future__ import annotations

import argparse
import io
import json
import os
import posixpath
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

# --------------------------------------------------------------------------- #
# File classification
# --------------------------------------------------------------------------- #
PYTHON_SUFFIXES = (".py", ".pyw", ".pyi")
MANIFEST_NAMES = ("setup.cfg", "pyproject.toml")
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1")
SCRIPT_NAMES = ("makefile", "gnumakefile")
ARCHIVE_SUFFIXES = (".zip", ".whl", ".egg", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")
BINARY_SUFFIXES = (".pyc", ".pyo", ".pyd", ".so", ".dll", ".dylib", ".exe", ".bin", ".msi", ".deb", ".rpm", ".jar")
#: Only these directories are skipped; attackers choose directory names, so "venv" etc. are scanned.
SKIP_DIRS = frozenset({".git", "__pycache__"})

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_ARCHIVE_TOTAL = 300 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
BATCH_SIZE = 25

ANALYZED_KINDS = ("python", "manifest", "script")


def classify(name: str, head: bytes = b"") -> str:
    """Classify a file by name (and shebang for extensionless files).

    Returns one of ``python``, ``manifest``, ``script``, ``archive``, ``binary``, ``other``.
    """
    lower = name.rsplit("/", 1)[-1].lower()
    if lower.endswith(PYTHON_SUFFIXES):
        return "python"
    if lower in MANIFEST_NAMES or lower.endswith(".pth") or (lower.endswith(".txt") and "requirement" in lower):
        return "manifest"
    if lower.endswith(SCRIPT_SUFFIXES) or lower in SCRIPT_NAMES:
        return "script"
    if lower.endswith(ARCHIVE_SUFFIXES):
        return "archive"
    if lower.endswith(BINARY_SUFFIXES):
        return "binary"
    if "." not in lower and head.startswith(b"#!"):
        first = head.split(b"\n", 1)[0]
        return "python" if b"python" in first else "script"
    return "other"


@dataclass
class ScanItem:
    """One discovered file (on disk or inside an archive)."""

    path: str                     # display path relative to the scan root ("a.zip!/pkg/x.py" for members)
    group: str                    # project the file belongs to (top-level folder or archive)
    inner_path: str               # path inside its project (drives install/test context in AST Master)
    kind: str
    size: int
    data: bytes | None = None
    status: str = "pending"       # pending | analyzed | skipped | error
    reason: str | None = None


@dataclass
class FileResult:
    """Per-file audit record."""

    path: str
    group: str
    kind: str
    size: int
    status: str
    verdict: str                  # MALICIOUS | SUSPICIOUS | BENIGN | NOT_ANALYZED | ERROR
    reason: str | None = None
    risk_score: float | None = None
    severity: str | None = None
    action: str | None = None
    predicted_attack_type: str | None = None
    scores: dict[str, Any] = field(default_factory=dict)
    ast_risk_factors: list[dict[str, Any]] = field(default_factory=list)
    astmaster_findings: list[dict[str, Any]] = field(default_factory=list)
    request_id: str | None = None


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #
def _safe_member(name: str) -> str | None:
    """Normalised member path, or ``None`` if it escapes the archive (zip-slip)."""
    norm = posixpath.normpath(name.replace("\\", "/"))
    if norm.startswith(("/", "../")) or norm == ".." or ":" in norm.split("/", 1)[0]:
        return None
    return norm


def _strip_root(names: list[str]) -> str:
    """Common single top-level directory of archive members (e.g. ``requests-main/``)."""
    tops = {n.split("/", 1)[0] for n in names if "/" in n}
    return tops.pop() + "/" if len(tops) == 1 and all("/" in n for n in names) else ""


def iter_archive(data: bytes, archive_path: str) -> Iterator[ScanItem]:
    """Yield members of a zip/tar archive held in memory, enforcing bomb/traversal limits."""
    members: list[tuple[str, int, Callable[[], bytes] | None, str | None]] = []
    if zipfile.is_zipfile(io.BytesIO(data)):
        zf = zipfile.ZipFile(io.BytesIO(data))
        for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
            if info.is_dir():
                continue
            ratio = info.file_size / max(info.compress_size, 1)
            issue = "compression ratio suggests a zip bomb" if ratio > MAX_COMPRESSION_RATIO and info.file_size > 1 << 20 else None
            members.append((info.filename, info.file_size, (lambda i=info: zf.read(i)), issue))
    else:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(data))
        except (tarfile.TarError, EOFError, OSError) as exc:
            yield ScanItem(archive_path, archive_path, "", "archive", len(data), status="error",
                           reason=f"unreadable archive: {exc}")
            return
        for info in tf.getmembers()[:MAX_ARCHIVE_MEMBERS]:
            if info.issym() or info.islnk():
                members.append((info.name, 0, None, f"link member -> {info.linkname}"))
            elif info.isfile():
                members.append((info.name, info.size, (lambda i=info: tf.extractfile(i).read()), None))  # type: ignore[union-attr]

    root = _strip_root([m[0] for m in members])
    total = 0
    for raw_name, size, reader, issue in members:
        safe = _safe_member(raw_name)
        display = f"{archive_path}!/{raw_name}"
        if safe is None:
            yield ScanItem(display, archive_path, raw_name, "other", size, status="skipped",
                           reason="path traversal member (zip-slip) - suspicious archive")
            continue
        inner = safe[len(root):] if root and safe.startswith(root) else safe
        kind = classify(safe)
        item = ScanItem(display, archive_path, inner, kind, size)
        if issue:
            item.status, item.reason = "skipped", issue
        elif kind == "archive":
            item.status, item.reason = "skipped", "nested archive (not unpacked)"
        elif kind not in ANALYZED_KINDS:
            item.status = "skipped"
            item.reason = "binary artifact (opaque to static analysis)" if kind == "binary" else "not a code/build file"
        elif size > MAX_FILE_BYTES:
            item.status, item.reason = "skipped", "file too large"
        elif total + size > MAX_ARCHIVE_TOTAL:
            item.status, item.reason = "skipped", "archive size budget exhausted"
        else:
            try:
                item.data = reader() if reader else b""
                total += len(item.data)
            except Exception as exc:  # corrupt member must not stop the scan
                item.status, item.reason = "error", f"unreadable member: {exc}"
        yield item


def discover(root: Path) -> Iterator[ScanItem]:
    """Recursively walk ``root`` (no symlink following) and archives within it."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for fname in sorted(filenames):
            full = Path(dirpath) / fname
            rel = full.relative_to(root).as_posix()
            group, _, inner = rel.partition("/")
            if not inner:
                group, inner = "(root)", rel
            try:
                st = full.lstat()
            except OSError as exc:
                yield ScanItem(rel, group, inner, "other", 0, status="error", reason=f"stat failed: {exc}")
                continue
            if stat.S_ISLNK(st.st_mode):
                yield ScanItem(rel, group, inner, "other", 0, status="skipped",
                               reason=f"symlink -> {os.readlink(full)} (not followed)")
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            try:
                with full.open("rb") as fh:
                    head = fh.read(256)
            except OSError as exc:
                yield ScanItem(rel, group, inner, "other", st.st_size, status="error", reason=f"unreadable: {exc}")
                continue
            kind = classify(fname, head)
            if kind == "archive":
                if st.st_size > MAX_ARCHIVE_TOTAL:
                    yield ScanItem(rel, rel, "", kind, st.st_size, status="skipped", reason="archive too large")
                    continue
                members = list(iter_archive(full.read_bytes(), rel))
                if len(members) == 1 and members[0].path == rel:  # the archive itself was unreadable
                    yield members[0]
                    continue
                yield ScanItem(rel, rel, "", kind, st.st_size, status="analyzed",
                               reason=f"archive: {len(members)} members inspected in memory")
                yield from members
                continue
            item = ScanItem(rel, group, inner, kind, st.st_size)
            if kind not in ANALYZED_KINDS:
                item.status = "skipped"
                item.reason = "binary artifact (opaque to static analysis)" if kind == "binary" else "not a code/build file"
            elif st.st_size > MAX_FILE_BYTES:
                item.status, item.reason = "skipped", "file too large"
            else:
                item.data = full.read_bytes()
            yield item


def project_name(root: Path, group: str, items: list[ScanItem]) -> str:
    """Best-effort package name for a project (pyproject/setup.cfg ``name``), else the folder name."""
    for item in items:
        if item.inner_path in ("pyproject.toml", "setup.cfg") and item.data:
            for line in item.data.decode("utf-8", "replace").splitlines():
                key, _, value = line.partition("=")
                if key.strip() == "name" and value.strip():
                    return value.strip().strip("\"'")
    return Path(group).name.split(".")[0] or group


# --------------------------------------------------------------------------- #
# Scoring backends
# --------------------------------------------------------------------------- #
class LocalBackend:
    """AST analyzer + trained models in-process (no services needed)."""

    mode = "local"

    def __init__(self, artifact_dir: Path) -> None:
        from ai_engine.ast_client import ASTServiceClient
        from ai_engine.predict import RiskEngine
        from ast_detection.analyzer import PackageAnalyzer

        analyzer = PackageAnalyzer()

        class _InProcessAST:
            def analyze_batch(self, packages: list[dict[str, Any]], chunk_size: int = 100) -> list[dict[str, Any]]:
                return [ASTServiceClient.verify(analyzer.analyze(p["name"], p["files"]), p["name"]) for p in packages]

        self.engine = RiskEngine(artifact_dir, client=_InProcessAST())  # type: ignore[arg-type]
        self.info = {"mode": "local", "artifacts": str(artifact_dir), "astmaster": analyzer.parser.backend_info(),
                     "model_trained_at": self.engine.scorer.metadata.get("created_at")}

    def assess(self, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score packages in-process."""
        return self.engine.assess(packages)


class ServiceBackend:
    """Use the running ``ai_engine`` container (which calls ``ast_detection``)."""

    mode = "service"

    def __init__(self, url: str) -> None:
        self.url = url.rstrip("/")
        health = self._call("GET", "/health")
        if not health.get("model", {}).get("loaded"):
            raise RuntimeError(f"AI engine at {self.url} has no model loaded: {health.get('model')}")
        self.info = {"mode": "service", "ai_engine": self.url, "astmaster": health["ast_service"].get("backend"),
                     "model_trained_at": health["model"].get("trained_at")}

    def _call(self, method: str, path: str, body: Any = None) -> dict[str, Any]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=300) as resp:  # noqa: S310 (internal URL)
                return json.loads(resp.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"{path}: HTTP {exc.code} {exc.read()[:300]!r}") from exc

    def assess(self, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Score packages via ``POST /assess``."""
        return self._call("POST", "/assess", {"packages": packages})["reports"]


# --------------------------------------------------------------------------- #
# Scan orchestration
# --------------------------------------------------------------------------- #
def verdict_for(report: dict[str, Any]) -> str:
    """Map the engine's decision onto audit verdicts."""
    if not report["flagged"]:
        return "BENIGN"
    return "MALICIOUS" if report["severity"] in ("CRITICAL", "HIGH") else "SUSPICIOUS"


def _decode(data: bytes) -> tuple[str, str | None]:
    try:
        return data.decode("utf-8"), None
    except UnicodeDecodeError:
        return data.decode("latin-1"), "not valid UTF-8 (decoded as latin-1)"


def _result_from_report(item: ScanItem, report: dict[str, Any], note: str | None) -> FileResult:
    layers = report["layers"]
    verdict = verdict_for(report)
    nodes = [n for n in report.get("ast_risky_nodes", [])
             if n["severity"] in ("critical", "high") or verdict != "BENIGN"]
    return FileResult(
        path=item.path, group=item.group, kind=item.kind, size=item.size, status="analyzed",
        verdict=verdict, reason=note, risk_score=report["risk_score"], severity=report["severity"],
        action=report["action"], predicted_attack_type=report["predicted_attack_type"],
        scores={"ast_static": layers["ast_static"]["score"], "ast_verdict": layers["ast_static"]["verdict"],
                "random_forest": layers["supervised"]["threat_probability"],
                "isolation_forest": layers["anomaly"]["percentile"],
                "ast_influence": report["ast_influence"]["delta"]},
        astmaster_findings=[f for f in report.get("findings", []) if f["severity"] in ("critical", "high")][:8],
        ast_risk_factors=[{"line": n["line"], "node": n["node"], "call": n["name"], "categories": n["categories"],
                           "severity": n["severity"], "import_time": n["module_level"]} for n in nodes[:10]],
        request_id=report.get("request_id"),
    )


def score_items(backend: LocalBackend | ServiceBackend, items: list[ScanItem], names: dict[str, str],
                progress: Callable[[int, int], None] | None = None) -> list[FileResult]:
    """Score analysable items in batches, isolating failures to the offending file."""
    results: list[FileResult] = []
    pending = [i for i in items if i.status == "pending"]
    for start in range(0, len(pending), BATCH_SIZE):
        batch = pending[start:start + BATCH_SIZE]
        prepared = []
        for item in batch:
            text, note = _decode(item.data or b"")
            prepared.append((item, note, {"name": names[item.group], "files": {item.inner_path: text},
                                          "request_id": f"scan-{uuid.uuid4().hex[:12]}"}))
        try:
            reports = backend.assess([p for _, _, p in prepared])
            results += [_result_from_report(it, rep, note) for (it, note, _), rep in zip(prepared, reports)]
        except Exception:
            for item, note, pkg in prepared:  # retry one by one: a bad file must not sink its batch
                try:
                    results.append(_result_from_report(item, backend.assess([pkg])[0], note))
                except Exception as exc:
                    results.append(FileResult(item.path, item.group, item.kind, item.size, "error", "ERROR",
                                              reason=f"{type(exc).__name__}: {str(exc)[:200]}"))
        if progress:
            progress(min(start + BATCH_SIZE, len(pending)), len(pending))
    return results


def run_scan(root: Path, backend: LocalBackend | ServiceBackend, quiet: bool = False) -> dict[str, Any]:
    """Discover, analyse and score everything under ``root``; return the audit report."""
    started = time.perf_counter()
    started_at = datetime.now(timezone.utc).isoformat()
    items = list(discover(root))
    by_group: dict[str, list[ScanItem]] = defaultdict(list)
    for it in items:
        by_group[it.group].append(it)
    names = {g: project_name(root, g, its) for g, its in by_group.items()}

    def progress(done: int, total: int) -> None:
        if not quiet:
            print(f"\r  scoring {done}/{total} files...", end="", file=sys.stderr, flush=True)

    scored = score_items(backend, items, names, progress)
    if not quiet:
        print(file=sys.stderr)
    scored_paths = {r.path for r in scored}
    others = [FileResult(it.path, it.group, it.kind, it.size, it.status,
                         "ERROR" if it.status == "error" else "NOT_ANALYZED", reason=it.reason)
              for it in items if it.path not in scored_paths]
    files = sorted(scored + others, key=lambda r: r.path)

    order = {"MALICIOUS": 0, "SUSPICIOUS": 1, "ERROR": 2, "BENIGN": 3, "NOT_ANALYZED": 4}
    groups = []
    for g in sorted(by_group):
        gf = [f for f in files if f.group == g]
        analyzed = [f for f in gf if f.status == "analyzed" and f.risk_score is not None]
        worst = min((f.verdict for f in gf if f.verdict != "NOT_ANALYZED"), key=order.__getitem__, default="NOT_ANALYZED")
        groups.append({
            "group": g, "package_name": names[g], "files_total": len(gf), "files_analyzed": len(analyzed),
            "verdicts": dict(Counter(f.verdict for f in gf)), "max_risk": max((f.risk_score for f in analyzed), default=None),
            "project_verdict": worst,
            "flagged_files": [f.path for f in gf if f.verdict in ("MALICIOUS", "SUSPICIOUS")],
        })

    verdicts = Counter(f.verdict for f in files)
    return {
        "scan_id": uuid.uuid4().hex,
        "root": str(root),
        "started_at": started_at,
        "duration_seconds": round(time.perf_counter() - started, 2),
        "engine": backend.info,
        "summary": {
            "files_discovered": len(files),
            "files_analyzed": sum(f.status == "analyzed" and f.risk_score is not None for f in files),
            "by_kind": dict(Counter(f.kind for f in files)),
            "verdicts": dict(verdicts),
            "skip_reasons": dict(Counter(f.reason for f in files if f.verdict == "NOT_ANALYZED")),
            "overall_verdict": "MALICIOUS" if verdicts["MALICIOUS"] else "SUSPICIOUS" if verdicts["SUSPICIOUS"]
            else "CLEAN",
        },
        "groups": groups,
        "files": [asdict(f) for f in files],
    }


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
_COLOR = {"MALICIOUS": "\033[1;31m", "SUSPICIOUS": "\033[1;33m", "BENIGN": "\033[32m", "ERROR": "\033[35m",
          "CLEAN": "\033[1;32m"}


def render_cli(report: dict[str, Any], show_all: bool = False, color: bool = True) -> str:
    """Human-readable summary of a scan report."""
    c = (lambda v: f"{_COLOR.get(v, '')}{v}\033[0m") if color else (lambda v: v)
    s = report["summary"]
    eng = report["engine"]
    am = eng.get("astmaster") or {}
    lines = [
        f"Supply chain scan of {report['root']}",
        f"  engine: {eng['mode']} mode | AST Master {'v' + str(am.get('rules_version')) if am.get('available') else 'unavailable'}"
        f" | model trained {eng.get('model_trained_at', '?')[:19]} | {report['duration_seconds']} s",
        f"  discovered {s['files_discovered']} files, analysed {s['files_analyzed']} "
        f"({', '.join(f'{k}: {v}' for k, v in sorted(s['by_kind'].items()))})",
        f"  verdicts: {', '.join(f'{c(k)} {v}' for k, v in sorted(s['verdicts'].items()))}",
        f"  OVERALL: {c(s['overall_verdict'])}",
        "",
        f"  {'project':<28}{'package':<12}{'analysed':>9}{'max risk':>10}   verdict",
    ]
    for g in report["groups"]:
        mr = f"{g['max_risk']:.3f}" if g["max_risk"] is not None else "-"
        lines.append(f"  {g['group']:<28}{g['package_name']:<12}{g['files_analyzed']:>9}{mr:>10}   {c(g['project_verdict'])}")
    shown = [f for f in report["files"] if show_all and f["status"] == "analyzed"
             or f["verdict"] in ("MALICIOUS", "SUSPICIOUS", "ERROR")]
    lines += ["", "  Flagged files:" if not show_all else "  Analysed files:"]
    if not shown:
        lines.append("    none")
    for f in sorted(shown, key=lambda f: -(f["risk_score"] or 0)):
        sc = f["scores"]
        lines.append(f"    {c(f['verdict']):<20} {f['path']}")
        if f["risk_score"] is not None:
            lines.append(f"        risk {f['risk_score']:.3f} | AST {sc['ast_verdict']} ({sc['ast_static']:.2f}) | "
                         f"RF {sc['random_forest']:.2f} | IF {sc['isolation_forest']:.2f} | type {f['predicted_attack_type']}")
        for n in f["ast_risk_factors"][:5]:
            lines.append(f"        line {n['line']:<5} {n['severity']:<8} {n['node']} {n['call']}  [{', '.join(n['categories'])}]"
                         f"{'  (runs at import)' if n['import_time'] else ''}")
        for fd in f["astmaster_findings"][:4]:
            lines.append(f"        AST Master: {fd['severity']} {fd['rule']} ({fd['context']}) line {fd['line']}")
        if f.get("reason") and f["verdict"] == "ERROR":
            lines.append(f"        {f['reason']}")
    return "\n".join(lines)


def _emit(event_type: str, **data: Any) -> None:
    """Best-effort scan lifecycle event to the dashboard (service mode)."""
    url = os.environ.get("EVENT_SINK_URL")
    if not url:
        return
    event = {"id": uuid.uuid4().hex, "ts": datetime.now(timezone.utc).isoformat(), "source": "scanner",
             "type": event_type, "request_id": None, "package": None, "data": data}
    req = urllib.request.Request(url, data=json.dumps({"events": [event]}).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "X-SCS-Token": os.environ.get("SCS_EVENT_TOKEN", "")})
    try:
        urllib.request.urlopen(req, timeout=3).close()  # noqa: S310 (internal URL)
    except Exception:
        pass


def default_target() -> Path:
    """``./supply_chain_lab`` inside the project if present, else the Desktop sibling ``../supply_chain_lab``."""
    inside = PROJECT_ROOT / "supply_chain_lab"
    return inside if inside.is_dir() else PROJECT_ROOT.parent / "supply_chain_lab"


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Exit codes: 0 clean, 3 threshold breached (``--fail-on``), 2 usage/setup error."""
    ap = argparse.ArgumentParser(description="Recursively scan a directory for supply chain attacks (AST + ML).")
    ap.add_argument("target", nargs="?", type=Path, default=None, help="Directory to scan (default: supply_chain_lab)")
    ap.add_argument("-o", "--output", type=Path, help="Write the full JSON report here")
    ap.add_argument("--mode", choices=["auto", "local", "service"], default="auto",
                    help="auto = service if AI_ENGINE_URL is set, else local")
    ap.add_argument("--ai-url", default=os.environ.get("AI_ENGINE_URL"), help="AI engine URL (service mode)")
    ap.add_argument("--artifacts", type=Path, default=Path(os.environ.get("ARTIFACT_DIR", PROJECT_ROOT / "artifacts")))
    ap.add_argument("--all", action="store_true", help="List every analysed file, not only flagged ones")
    ap.add_argument("--fail-on", choices=["suspicious", "malicious"], help="Exit 3 if any file reaches this verdict")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-q", "--quiet", action="store_true")
    args = ap.parse_args(argv)

    target = (args.target or default_target()).resolve()
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 2
    mode = args.mode if args.mode != "auto" else ("service" if args.ai_url else "local")
    try:
        backend: LocalBackend | ServiceBackend = (
            ServiceBackend(args.ai_url) if mode == "service" else LocalBackend(args.artifacts))
    except Exception as exc:
        print(f"error: cannot start {mode} backend: {exc}", file=sys.stderr)
        if mode == "local":
            print("hint: train first (python -m ai_engine.train) or point --artifacts at a trained model", file=sys.stderr)
        return 2

    _emit("scan.started", root=str(target))
    report = run_scan(target, backend, quiet=args.quiet)
    _emit("scan.completed", root=str(target), summary=report["summary"], groups=report["groups"],
          flagged=[f for f in report["files"] if f["verdict"] in ("MALICIOUS", "SUSPICIOUS")])
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    print(render_cli(report, show_all=args.all, color=not args.no_color and sys.stdout.isatty()))
    if args.output:
        print(f"\n  full report: {args.output}")
    if args.fail_on:
        bad = {"suspicious": ("SUSPICIOUS", "MALICIOUS"), "malicious": ("MALICIOUS",)}[args.fail_on]
        if any(f["verdict"] in bad for f in report["files"]):
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
