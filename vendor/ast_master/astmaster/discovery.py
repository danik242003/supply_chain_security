"""Fast directory traversal and incremental, parallel parsing of Python files.

Speed comes from avoiding work rather than from a clever walker:

* ``os.scandir`` gets file types from the directory read, without a stat per entry.
* Irrelevant directories are pruned before descending into them.
* A cheap byte search skips parsing files that can't contain a Thread.
* An (mtime, size) cache skips files that haven't changed since the last scan.
* Workers return plain metadata because pickling AST objects is expensive.
"""

from __future__ import annotations

import ast
import multiprocessing
import os
import threading
import time
from concurrent.futures import ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from dataclasses import dataclass, field
from typing import Callable, Iterator

from .models import Issue, ScanResult, Severity

DEFAULT_PRUNE = frozenset({
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", ".tox", ".eggs",
})
MAX_FILE_BYTES = 5 * 1024 * 1024
# Measured on the VM: a warm pool wins from about 0.8 MB of source. Recheck on the Pi.
PARALLEL_MIN_BYTES = 1024 * 1024


def _sort_key(entry: os.DirEntry) -> tuple[bool, str]:
    return (not entry.is_dir(follow_symlinks=False), entry.name)


def list_dir(path: str) -> list[os.DirEntry]:
    """One directory, folders first. Uses no stat calls on Linux."""
    with os.scandir(path) as iterator:
        return sorted(iterator, key=_sort_key)


def iter_tree(
    root: str,
    prune: frozenset[str] = frozenset(),
    on_error: Callable[[OSError], None] | None = None,
    sort: bool = False,
) -> Iterator[os.DirEntry]:
    """Yield every entry under ``root`` without recursion or following symlinks."""
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=_sort_key, reverse=True) if sort else list(iterator)
        except OSError as error:
            if on_error:
                on_error(error)
            continue
        if sort:
            entries.reverse()
        subdirs = []
        for entry in entries:
            yield entry
            if entry.is_dir(follow_symlinks=False) and entry.name not in prune:
                subdirs.append(entry.path)
        pending.extend(reversed(subdirs))


def discover_python_files(root: str, prune: frozenset[str] = DEFAULT_PRUNE) -> Iterator[os.DirEntry]:
    for entry in iter_tree(root, prune):
        if entry.name.endswith(".py") and entry.is_file(follow_symlinks=False):
            yield entry


@dataclass(slots=True)
class FileReport:
    path: str
    scan: ScanResult | None = None
    has_threads: bool = False
    feasible: bool = False
    template_count: int = 0
    issues: list[Issue] = field(default_factory=list)
    parsed: bool = False


@dataclass(slots=True)
class ScanStats:
    files: int = 0
    cache_hits: int = 0
    parsed: int = 0
    skipped_no_thread: int = 0
    skipped_too_large: int = 0
    failed: int = 0
    used_pool: bool = False
    seconds: float = 0.0


@dataclass(slots=True)
class TreeReport:
    reports: list[FileReport]
    stats: ScanStats


def process_file(path: str, threads_only: bool) -> FileReport:
    """Analyze one file. Runs inside a pool worker, so it returns no AST objects."""
    from .pipeline import analyze_source, parse_and_scan

    report = FileReport(path)
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        report.issues.append(Issue(Severity.ERROR, "unreadable", str(error)))
        return report
    if b"Thread" not in data:
        # threading.Thread can't appear in the AST unless it appears in the text.
        if threads_only:
            return report
        try:
            _, scanner = parse_and_scan(data, path)
        except (SyntaxError, ValueError, RecursionError, MemoryError) as error:
            report.issues.append(Issue(Severity.ERROR, "syntax-error", str(error)))
            return report
        report.scan = scanner.result
        report.parsed = True
        return report

    result = analyze_source(data, path)
    report.scan = result.scan
    report.parsed = True
    report.has_threads = bool(result.scan.threads)
    report.feasible = result.feasible
    report.template_count = len(result.templates)
    report.issues = result.issues
    return report


def _process_file_star(job: tuple[str, bool]) -> FileReport:
    return process_file(*job)


class TreeScanner:
    """Scans directory trees, reusing earlier results for unchanged files."""

    def __init__(self, workers: int | None = None) -> None:
        self._workers = workers or max(1, (os.cpu_count() or 2) - 1)
        self._cache: dict[tuple[str, bool], tuple[int, int, FileReport]] = {}
        self._lock = threading.Lock()
        self._pool: ProcessPoolExecutor | None = None

    def _get_pool(self) -> ProcessPoolExecutor:
        with self._lock:
            if self._pool is None:
                # Never fork from a threaded web server: it can deadlock children.
                context = multiprocessing.get_context("forkserver")
                context.set_forkserver_preload(["astmaster.pipeline"])
                self._pool = ProcessPoolExecutor(self._workers, mp_context=context)
            return self._pool

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, None
        if pool:
            pool.shutdown(cancel_futures=True)

    def _run_jobs(self, jobs: list[tuple[str, int, int]], threads_only: bool, use_pool: bool) -> Iterator[FileReport]:
        work = [(path, threads_only) for path, _, _ in jobs]
        done = 0
        if use_pool:
            chunk = max(1, len(work) // (self._workers * 8))
            try:
                for report in self._get_pool().map(_process_file_star, work, chunksize=chunk):
                    yield report
                    done += 1
                return
            except BrokenProcessPool:
                # A worker died, perhaps killed for memory on a small board.
                # Discard the pool and finish in this process.
                self.close()
        for job in work[done:]:
            yield _process_file_star(job)

    def scan(self, root: str, threads_only: bool = False, prune: frozenset[str] = DEFAULT_PRUNE) -> TreeReport:
        started = time.perf_counter()
        stats = ScanStats()
        reports: list[FileReport] = []
        jobs: list[tuple[str, int, int]] = []
        total_bytes = 0

        for entry in discover_python_files(root, prune):
            stats.files += 1
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError as error:
                stats.failed += 1
                reports.append(FileReport(entry.path, issues=[Issue(Severity.ERROR, "unreadable", str(error))]))
                continue
            if info.st_size > MAX_FILE_BYTES:
                stats.skipped_too_large += 1
                reports.append(FileReport(entry.path, issues=[
                    Issue(Severity.WARNING, "too-large", f"Skipped: {info.st_size} bytes.")
                ]))
                continue
            with self._lock:
                cached = self._cache.get((entry.path, threads_only))
            if cached and cached[:2] == (info.st_mtime_ns, info.st_size):
                stats.cache_hits += 1
                reports.append(cached[2])
                continue
            jobs.append((entry.path, info.st_mtime_ns, info.st_size))
            total_bytes += info.st_size

        use_pool = self._workers > 1 and total_bytes >= PARALLEL_MIN_BYTES
        stats.used_pool = use_pool
        for (path, mtime, size), report in zip(jobs, self._run_jobs(jobs, threads_only, use_pool)):
            reports.append(report)
            with self._lock:
                self._cache[(path, threads_only)] = (mtime, size, report)
            if report.parsed:
                stats.parsed += 1
            elif report.issues:
                stats.failed += 1
            else:
                stats.skipped_no_thread += 1

        reports.sort(key=lambda r: r.path)
        stats.seconds = time.perf_counter() - started
        return TreeReport(reports, stats)
