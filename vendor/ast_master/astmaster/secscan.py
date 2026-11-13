"""Scan a whole repository: files -> signals (cached) -> findings -> verdict."""

from __future__ import annotations

import hashlib
import io
import multiprocessing
import os
import posixpath
import secrets
import stat
import threading
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from .clustering import FEATURE_VERSION, ClusterService, build_vector, has_capabilities
from .db import ScanRepository, SignalCache, SignatureRepository
from .prefilter import fast_imports, scan_text
from .security import (
    RULES, RULES_VERSION, SEVERITIES, FileSignals, Finding, file_kind, rate_file, risk_score,
    scan_pth, scan_pyproject, scan_python, scan_requirements, scan_script, scan_setup_cfg, verdict_for,
)

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_FILES = 50000
MAX_ARCHIVE_TOTAL = 500 * 1024 * 1024
PARALLEL_MIN_BYTES = 1024 * 1024
# While walking, write file rows after this many files or this long, whichever comes first.
_FLUSH_FILES = 200
_FLUSH_SECONDS = 0.5
SEED_PATH = Path(__file__).with_name("signature_seed.json")
# Only these are skipped. Names like venv or node_modules are scanned, because an
# attacker chooses a directory's name.
SKIP_DIRS = frozenset({".git", "__pycache__"})
_BINARY_SUFFIXES = (
    ".pyc", ".pyo", ".pyd", ".so", ".dll", ".dylib", ".exe", ".bin", ".whl", ".egg", ".msi", ".deb", ".rpm",
    ".jar", ".com",
)
_SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1")
_PYTHON_SUFFIXES = (".py", ".pyw")

_HANDLERS = {
    "python": scan_python, "pth": scan_pth, "requirements": scan_requirements,
    "pyproject": scan_pyproject, "setupcfg": scan_setup_cfg, "script": scan_script,
}


def handler_for(path: str) -> str | None:
    """Pick a scanner from the name alone. None means it may need a shebang check."""
    name = posixpath.basename(path).lower()
    if name.endswith(_PYTHON_SUFFIXES):
        return "python"
    if name.endswith(".pth"):
        return "pth"
    if name == "pyproject.toml":
        return "pyproject"
    if name == "setup.cfg":
        return "setupcfg"
    if name.endswith(_SCRIPT_SUFFIXES) or name in ("makefile",):
        return "script"
    if name.endswith(".txt") and "requirement" in name:
        return "requirements"
    if name.endswith(_BINARY_SUFFIXES):
        return "binary"
    return None if "." not in name else "skip"


def shebang_handler(head: bytes) -> str:
    if not head.startswith(b"#!"):
        return "skip"
    first = head.split(b"\n", 1)[0]
    return "python" if b"python" in first else "script"


@dataclass(slots=True)
class Item:
    """One repository entry, on disk or held in memory."""

    path: str
    disk_path: str | None = None
    data: bytes | None = None
    size: int = 0
    link_target: str | None = None
    error: str | None = None


@dataclass(slots=True)
class SecurityReport:
    scan_id: str
    name: str
    source: str
    created_at: float
    verdict: str
    rules_version: int
    stats: dict
    findings: list[Finding] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    risk_score: int = 0


def analyze_bytes(data: bytes, handler: str, path: str) -> FileSignals:
    """Runs in a pool worker. Contains no AST objects in its result."""
    from .pipeline import analyze_source

    signals = _HANDLERS[handler](data)
    if handler == "python" and b"Thread" in data and signals.status == "ok":
        parallel = analyze_source(data, path, security=False)
        signals.thread_count = len(parallel.scan.threads)
        signals.parallel_feasible = parallel.feasible
    return signals


def _pool_job(job: tuple[str | None, bytes | None, str, str]) -> FileSignals:
    disk_path, data, handler, path = job
    if data is None:
        with open(disk_path, "rb") as handle:
            data = handle.read()
    return analyze_bytes(data, handler, path)


def iter_directory(root: str) -> tuple[Iterator[Item], list[Finding]]:
    """Walk a folder without following symlinks. Real virtualenvs are reported and skipped."""
    notes: list[Finding] = []

    def walk() -> Iterator[Item]:
        pending = [root]
        while pending:
            directory = pending.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries = list(iterator)
            except OSError as error:
                relative = _printable_path(os.path.relpath(directory, root))
                yield Item(relative, error=str(error.strerror))
                continue
            for entry in entries:
                relative = _printable_path(os.path.relpath(entry.path, root).replace(os.sep, "/"))
                if entry.is_symlink():
                    try:
                        yield Item(relative, link_target=os.readlink(entry.path))
                    except OSError:
                        pass
                elif entry.is_dir(follow_symlinks=False):
                    if entry.name in SKIP_DIRS:
                        continue
                    if _is_real_venv(entry.path):
                        rule = RULES["skipped-venv"]
                        notes.append(Finding("skipped-venv", rule.install, "repository", relative, 0, rule.message))
                        continue
                    pending.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    try:
                        size = entry.stat(follow_symlinks=False).st_size
                    except OSError as error:
                        yield Item(relative, error=str(error.strerror))
                        continue
                    yield Item(relative, disk_path=entry.path, size=size)

    return walk(), notes


def _printable_path(path: str) -> str:
    """A file name that isn't valid UTF-8 can't be stored as text, and mustn't stop the scan."""
    return path.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def _is_real_venv(path: str) -> bool:
    """A config file alone could be planted to dodge the scan: require an interpreter link too."""
    if not os.path.isfile(os.path.join(path, "pyvenv.cfg")):
        return False
    return any(
        os.path.islink(os.path.join(path, "bin", name)) for name in ("python", "python3")
    )


def items_from_zip(data: bytes) -> list[Item]:
    """Read an archive in memory. Nothing is extracted, so path tricks can't touch the disk."""
    items: list[Item] = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for info in archive.infolist()[:MAX_ARCHIVE_FILES]:
            if info.is_dir():
                continue
            path = clean_upload_path(info.filename)
            if not path:
                continue
            if stat.S_ISLNK(info.external_attr >> 16):
                target = archive.read(info)[:4096].decode("utf-8", "replace")
                items.append(Item(path, link_target=target))
                continue
            if info.flag_bits & 0x1:
                items.append(Item(path, error="encrypted archive entry"))
                continue
            if info.file_size > MAX_FILE_BYTES:
                items.append(Item(path, size=info.file_size))
                continue
            total += info.file_size
            if total > MAX_ARCHIVE_TOTAL:
                items.append(Item(path, error="archive expands past the size limit, so the rest wasn't scanned"))
                break
            try:
                items.append(Item(path, data=archive.read(info), size=info.file_size))
            except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, ValueError) as error:
                items.append(Item(path, error=f"corrupt entry: {error}"))
    return items


def clean_upload_path(raw: str) -> str:
    """Uploaded paths are only labels. Normalize them so they can't mislead a reader."""
    raw = raw.replace("\\", "/").replace("\0", "")
    parts = [p for p in raw.split("/") if p not in ("", ".", "..")]
    return "/".join(parts)


def strip_common_root(items: list[Item]) -> None:
    """A folder upload puts every path under one top folder, which isn't part of the repo."""
    roots = {item.path.partition("/")[0] for item in items if "/" in item.path}
    if len(roots) == 1 and all("/" in item.path for item in items):
        prefix = len(next(iter(roots))) + 1
        for item in items:
            item.path = item.path[prefix:]


class SecurityScanner:
    def __init__(
        self,
        cache: SignalCache,
        reports: ScanRepository,
        signatures: SignatureRepository,
        workers: int | None = None,
    ) -> None:
        self._cache = cache
        self._reports = reports
        signatures.seed_if_empty(SEED_PATH, FEATURE_VERSION)
        self._clusters = ClusterService(lambda: signatures.load(FEATURE_VERSION))
        self._workers = workers or max(1, (os.cpu_count() or 2) - 1)
        self._pool: ProcessPoolExecutor | None = None
        self._lock = threading.Lock()

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, None
        if pool:
            pool.shutdown(cancel_futures=True)

    def _get_pool(self) -> ProcessPoolExecutor:
        with self._lock:
            if self._pool is None:
                context = multiprocessing.get_context("forkserver")
                context.set_forkserver_preload(["astmaster.secscan"])
                self._pool = ProcessPoolExecutor(self._workers, mp_context=context)
            return self._pool

    def scan_directory(self, root: str, name: str | None = None) -> SecurityReport:
        items, notes = iter_directory(root)
        full_path = os.path.abspath(root)
        return self.scan_items(items, name or os.path.basename(full_path), "folder", notes, _printable_path(full_path))

    def warm_up(self) -> None:
        """Load the clustering model ahead of the first scan."""
        self._clusters.model()

    def scan_items(
        self, items: Iterable[Item], name: str, source: str, notes: list[Finding] | None = None,
        root: str | None = None,
    ) -> SecurityReport:
        """Scan, logging to the database as it goes. A repository is identified by source and root."""
        scan_id = secrets.token_urlsafe(9)
        created_at = time.time()
        self._reports.begin(scan_id, name, source, root or name, created_at, RULES_VERSION)
        try:
            return self._scan_items(scan_id, created_at, items, name, source, notes)
        except BaseException as error:
            self._reports.fail(scan_id, f"{type(error).__name__}: {error}")
            raise

    def _scan_items(
        self, scan_id: str, created_at: float, items: Iterable[Item], name: str, source: str,
        notes: list[Finding] | None,
    ) -> SecurityReport:
        started = time.perf_counter()
        notes = notes if notes is not None else []
        findings: list[Finding] = []
        file_rows: dict[str, dict] = {}
        immediate: list[Finding] = []
        pending: list[tuple[Item, str, str]] = []     # Needs deep analysis: item, handler, sha256.
        filtered: dict[str, FileSignals] = {}         # Cleared by Phase 1.
        counts = {"entries": 0, "bytes": 0}
        phase1 = {"python_files": 0, "flagged": 0, "entry_points": 0, "cleared": 0, "seconds": 0.0}
        unflushed: list[dict] = []
        last_flush = time.monotonic()

        def flush_files() -> None:
            nonlocal last_flush
            if unflushed:
                self._reports.record_files(scan_id, unflushed)
                unflushed.clear()
            last_flush = time.monotonic()

        def row(path: str, size: int, status: str, sha: str | None = None) -> dict:
            file_rows[path] = {
                "path": path, "sha256": sha, "size": size, "status": status, "worst_severity": None,
                "thread_count": 0, "parallel_feasible": 0, "phase1": "", "phase1_reasons": "",
                "functions": 0, "loops": 0, "cluster": None, "nearest_signature": None, "risk_score": None,
            }
            unflushed.append(file_rows[path])
            if len(unflushed) >= _FLUSH_FILES or time.monotonic() - last_flush >= _FLUSH_SECONDS:
                flush_files()
            return file_rows[path]

        def flag(path: str, rule_name: str, detail: str = "", line: int = 0) -> None:
            rule = RULES[rule_name]
            immediate.append(Finding(rule_name, rule.install, "repository", path, line, rule.message, detail))

        for item in items:
            counts["entries"] += 1
            if item.error:
                row(item.path, item.size, "unreadable")
                flag(item.path, "unreadable", item.error)
                continue
            if item.link_target is not None:
                if _escapes(item.path, item.link_target):
                    row(item.path, 0, "symlink")
                    flag(item.path, "symlink-escape", item.link_target)
                continue
            handler = handler_for(item.path)
            if handler is None:
                head = item.data[:256] if item.data is not None else _read_head(item.disk_path)
                handler = shebang_handler(head)
            if handler == "skip":
                continue
            if handler == "binary":
                row(item.path, item.size, "opaque")
                flag(item.path, "opaque-binary")
                continue
            if item.size > MAX_FILE_BYTES:
                row(item.path, item.size, "too-large")
                flag(item.path, "too-large", f"{item.size} bytes")
                continue
            data = item.data
            if data is None:
                try:
                    with open(item.disk_path, "rb") as handle:
                        data = handle.read(MAX_FILE_BYTES + 1)
                except OSError as error:
                    row(item.path, item.size, "unreadable")
                    flag(item.path, "unreadable", str(error.strerror))
                    continue
            counts["bytes"] += len(data)
            info = row(item.path, len(data), "ok")
            if handler == "python":
                phase1["python_files"] += 1
                filter_started = time.perf_counter()
                result = scan_text(data, item.path)
                needs_threads = b"Thread" in data
                phase1["seconds"] += time.perf_counter() - filter_started
                info["phase1_reasons"] = ", ".join(result.reasons)
                if not result.flagged and not needs_threads:
                    info["phase1"] = "cleared"
                    info["status"] = "filtered"
                    phase1["cleared"] += 1
                    filtered[item.path] = FileSignals(status="filtered", local_imports=fast_imports(data))
                    continue
                if result.reasons == ["entry point"]:
                    info["phase1"] = "entry point"
                    phase1["entry_points"] += 1
                elif result.flagged:
                    info["phase1"] = "flagged"
                    phase1["flagged"] += 1
                else:
                    info["phase1"] = "threads"
                    info["phase1_reasons"] = "Thread (for the Mediator)"
            sha = hashlib.sha256(data).hexdigest()
            info["sha256"] = sha
            pending.append((item, handler, sha))

        flush_files()
        self._reports.checkpoint(scan_id, "phase2", list(file_rows.values()), immediate + notes)

        # Phase 2: AST and rules, for what Phase 1 didn't clear.
        phase2_started = time.perf_counter()
        signals_by_key = self._cache.get_many(((sha, h) for _, h, sha in pending), RULES_VERSION)
        cache_hits = sum((sha, h) in signals_by_key for _, h, sha in pending)
        misses: dict[tuple[str, str], tuple[Item, str]] = {}
        for item, handler, sha in pending:
            if (sha, handler) not in signals_by_key:
                misses.setdefault((sha, handler), (item, handler))
        fresh = self._run(list(misses.items()))
        signals_by_key.update(fresh)
        self._cache.put_many(((sha, h, s) for (sha, h), s in fresh.items()), RULES_VERSION)

        by_path = {item.path: signals_by_key[(sha, h)] for item, h, sha in pending}
        reached = _install_reach({**by_path, **filtered})
        rated: list[tuple[str, FileSignals, list[Finding]]] = []
        for item, handler, sha in pending:
            signals = by_path[item.path]
            info = file_rows[item.path]
            info["status"] = signals.status
            info["thread_count"] = signals.thread_count
            info["parallel_feasible"] = int(signals.parallel_feasible)
            info["functions"] = signals.structure.get("functions", 0)
            info["loops"] = signals.structure.get("loops", 0)
            file_findings = rate_file(item.path, signals, item.path in reached)
            findings.extend(file_findings)
            if handler == "python":
                rated.append((item.path, signals, file_findings))
        phase2_seconds = time.perf_counter() - phase2_started
        _rate_files(findings + immediate + notes, file_rows)
        self._reports.checkpoint(scan_id, "phase3", list(file_rows.values()), findings + immediate + notes)

        # Phase 3: compare structure with known attack patterns.
        phase3_started = time.perf_counter()
        model = self._clusters.model()
        matches = 0
        vectors = 0
        if model is not None:
            for path, signals, file_findings in rated:
                vector = build_vector(path, signals, file_findings)
                if not has_capabilities(vector):
                    continue
                vectors += 1
                match = model.classify(vector)
                if match is None:
                    continue
                matches += 1
                file_rows[path]["cluster"] = match.cluster
                file_rows[path]["nearest_signature"] = match.signature
                context = _strongest_context(file_findings)
                rule = RULES["cluster-attack-match"]
                severity = {"install": rule.install, "import": rule.imported, "runtime": rule.runtime}[context]
                findings.append(Finding(
                    "cluster-attack-match", severity, context, path, 0, rule.message,
                    f"Nearest signature: {match.signature} ({match.category}), distance {match.distance}",
                ))
        phase3_seconds = time.perf_counter() - phase3_started

        findings.extend(immediate)
        findings.extend(notes)
        _gate_parallel(findings, file_rows)
        _rate_files(findings, file_rows)
        findings.sort(key=lambda f: (-SEVERITIES.index(f.severity), f.path, f.line))

        phase1["seconds"] = round(phase1["seconds"], 4)
        deep_python = len(rated)
        stats = {
            **counts,
            "scanned": len(pending) + len(filtered),
            "cache_hits": cache_hits,
            "misses": len(misses),
            "not_scanned": sum(f.rule in ("too-large", "unparsed", "too-complex", "unreadable", "opaque-binary", "skipped-venv") for f in findings),
            "seconds": round(time.perf_counter() - started, 4),
            "phase1": phase1,
            "phase2": {"python_files": deep_python, "other_files": len(pending) - deep_python, "seconds": round(phase2_seconds, 4)},
            "phase3": {
                "status": "ran" if model is not None else f"unavailable: {self._clusters.unavailable}",
                "vectors": vectors, "matches": matches, "seconds": round(phase3_seconds, 4),
            },
        }
        report = SecurityReport(
            scan_id, name, source, created_at, verdict_for(findings), RULES_VERSION,
            stats, findings, sorted(file_rows.values(), key=lambda f: f["path"]), risk_score(findings),
        )
        self._reports.finish(report)
        return report

    def _run(self, jobs: list[tuple[tuple[str, str], tuple[Item, str]]]) -> dict[tuple[str, str], FileSignals]:
        work = [(item.disk_path, item.data, handler, item.path) for _, (item, handler) in jobs]
        total = sum(item.size for _, (item, _) in jobs)
        results: list[FileSignals] = []
        if self._workers > 1 and total >= PARALLEL_MIN_BYTES:
            chunk = max(1, len(work) // (self._workers * 8))
            try:
                for result in self._get_pool().map(_pool_job, work, chunksize=chunk):
                    results.append(result)
            except BrokenProcessPool:
                # A worker died, perhaps killed for memory on a small board. Finish here.
                self.close()
        for job in work[len(results):]:
            results.append(_pool_job(job))
        return {key: result for (key, _), result in zip(jobs, results)}


def _read_head(path: str | None) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(256)
    except (OSError, TypeError):
        return b""


def _escapes(path: str, target: str) -> bool:
    if target.startswith(("/", "\\")) or (len(target) > 1 and target[1] == ":"):
        return True
    return posixpath.normpath(posixpath.join(posixpath.dirname(path), target.replace("\\", "/"))).startswith("..")


def _install_reach(by_path: dict[str, FileSignals]) -> set[str]:
    """Local modules that an install file imports or executes run during install too.

    An install file reaches only code in or below its own folder. Otherwise a setup.py nested
    deep in a project would claim `import os` means that project's unrelated os.py.
    """
    modules: dict[str, list[str]] = {}
    for path in by_path:
        if not path.endswith((".py", ".pyw")):
            continue
        dotted = path.rsplit(".", 1)[0].replace("/", ".")
        if dotted.endswith(".__init__"):
            dotted = dotted[: -len(".__init__")]
        parts = dotted.split(".")
        # Match any suffix, so a src/ layout or a nested project still resolves.
        for start in range(len(parts)):
            modules.setdefault(".".join(parts[start:]), []).append(path)

    def resolve(importer: str, module: str, level: int) -> list[str]:
        if level:
            base = importer.rsplit("/", level)[0] if importer.count("/") >= level else ""
            module = ".".join(p for p in (base.replace("/", "."), module) if p)
        found: list[str] = []
        parts = module.split(".")
        for end in range(1, len(parts) + 1):
            found += modules.get(".".join(parts[:end]), ())
        return found

    reached: set[str] = set()
    # Shallowest first: a file reached from a parent folder has already had the wider search.
    entries = sorted((p for p in by_path if file_kind(p) == "install"), key=lambda p: p.count("/"))
    for entry in entries:
        folder = posixpath.dirname(entry)
        prefix = f"{folder}/" if folder else ""
        pending = [entry]
        while pending:
            path = pending.pop()
            signals = by_path[path]
            targets: list[str] = []
            for module, level in signals.local_imports:
                targets += resolve(path, module, level)
            for target in signals.exec_targets:
                normalized = posixpath.normpath(target.lstrip("./"))
                candidates = [normalized, posixpath.join(posixpath.dirname(path), normalized)]
                targets += [c for c in candidates if c in by_path]
                targets += [p for p in by_path if p.endswith("/" + normalized)]
            for target in targets:
                if target.startswith(prefix) and target not in reached and target != path:
                    reached.add(target)
                    pending.append(target)
    return reached


def _rate_files(findings: list[Finding], rows: dict[str, dict]) -> None:
    """Each file's worst severity and risk score, from the findings known so far."""
    by_path: dict[str, list[Finding]] = {path: [] for path in rows}
    for finding in findings:
        if finding.path in by_path:
            by_path[finding.path].append(finding)
    for path, found in by_path.items():
        rows[path]["risk_score"] = risk_score(found)
        rows[path]["worst_severity"] = max((f.severity for f in found), key=SEVERITIES.index, default=None)


def _gate_parallel(findings: list[Finding], rows: dict[str, dict]) -> None:
    """A file with a critical finding can't be a parallel candidate."""
    for finding in findings:
        if finding.severity == "critical" and finding.path in rows:
            rows[finding.path]["parallel_feasible"] = 0


def _strongest_context(findings: list[Finding]) -> str:
    contexts = {f.context for f in findings}
    for context in ("install", "import"):
        if context in contexts:
            return context
    return "runtime"
