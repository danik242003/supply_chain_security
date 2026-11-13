"""SQLite layer: the Master Node's single source of truth.

Only this module knows SQL. Each thread gets its own connection, WAL mode lets
readers continue during writes, and schema changes are numbered migrations.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import threading
import time
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

from .models import DatabaseLocationError, Issue, ScanResult, Severity
from .pipeline import AnalysisResult
from .security import Finding, FileSignals, payload_fields
from .templates import Template, TemplateSite

MIGRATIONS = (
    """
    CREATE TABLE analyses (
        analysis_id TEXT PRIMARY KEY,
        filename TEXT NOT NULL,
        created_at REAL NOT NULL,
        feasible INTEGER NOT NULL,
        scan_json TEXT NOT NULL,
        issues_json TEXT NOT NULL,
        transformed_source TEXT
    );
    CREATE TABLE templates (
        template_id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        source TEXT NOT NULL
    );
    CREATE TABLE analysis_templates (
        analysis_id TEXT NOT NULL REFERENCES analyses ON DELETE CASCADE,
        template_id TEXT NOT NULL REFERENCES templates,
        sites_json TEXT NOT NULL,
        PRIMARY KEY (analysis_id, template_id)
    );
    CREATE INDEX analysis_templates_by_template ON analysis_templates (template_id);
    CREATE TABLE tasks (
        task_id TEXT PRIMARY KEY,
        template_id TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'done', 'failed')),
        args_repr TEXT NOT NULL,
        kwargs_repr TEXT NOT NULL,
        reply_json TEXT NOT NULL DEFAULT '{}',
        submitted_at REAL NOT NULL,
        finished_at REAL
    );
    CREATE INDEX tasks_by_status ON tasks (status);
    CREATE TABLE security_scans (
        scan_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        source TEXT NOT NULL,
        created_at REAL NOT NULL,
        verdict TEXT NOT NULL,
        rules_version INTEGER NOT NULL,
        stats_json TEXT NOT NULL
    );
    CREATE TABLE scan_files (
        scan_id TEXT NOT NULL REFERENCES security_scans ON DELETE CASCADE,
        path TEXT NOT NULL,
        sha256 TEXT,
        size INTEGER NOT NULL,
        status TEXT NOT NULL,
        worst_severity TEXT,
        thread_count INTEGER NOT NULL DEFAULT 0,
        parallel_feasible INTEGER NOT NULL DEFAULT 0,
        PRIMARY KEY (scan_id, path)
    );
    CREATE TABLE findings (
        finding_id INTEGER PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES security_scans ON DELETE CASCADE,
        path TEXT NOT NULL,
        rule TEXT NOT NULL,
        severity TEXT NOT NULL,
        context TEXT NOT NULL,
        line INTEGER NOT NULL,
        message TEXT NOT NULL,
        detail TEXT NOT NULL,
        snippet TEXT NOT NULL
    );
    CREATE INDEX findings_by_scan ON findings (scan_id);
    CREATE TABLE signal_cache (
        sha256 TEXT NOT NULL,
        handler TEXT NOT NULL,
        rules_version INTEGER NOT NULL,
        signals_json TEXT NOT NULL,
        PRIMARY KEY (sha256, handler, rules_version)
    ) WITHOUT ROWID;
    """,
    """
    ALTER TABLE scan_files ADD COLUMN phase1 TEXT NOT NULL DEFAULT '';
    ALTER TABLE scan_files ADD COLUMN phase1_reasons TEXT NOT NULL DEFAULT '';
    ALTER TABLE scan_files ADD COLUMN functions INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE scan_files ADD COLUMN loops INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE scan_files ADD COLUMN cluster INTEGER;
    ALTER TABLE scan_files ADD COLUMN nearest_signature TEXT;
    CREATE TABLE signatures (
        signature_id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        label TEXT NOT NULL CHECK (label IN ('attack', 'benign')),
        category TEXT NOT NULL,
        feature_version INTEGER NOT NULL,
        vector_json TEXT NOT NULL,
        UNIQUE (name, label, feature_version)
    );
    """,
    # Scans from before this migration keep risk_score NULL and have no repository or
    # payload rows: that data can't be rebuilt honestly from what they stored.
    """
    CREATE TABLE repositories (
        repo_id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        source TEXT NOT NULL,
        root TEXT NOT NULL,
        first_seen REAL NOT NULL,
        last_scanned REAL NOT NULL,
        last_verdict TEXT,
        last_risk_score INTEGER,
        UNIQUE (source, root)
    );
    ALTER TABLE security_scans ADD COLUMN repo_id INTEGER REFERENCES repositories ON DELETE SET NULL;
    ALTER TABLE security_scans ADD COLUMN risk_score INTEGER;
    ALTER TABLE security_scans ADD COLUMN status TEXT NOT NULL DEFAULT 'complete';
    ALTER TABLE security_scans ADD COLUMN stage TEXT NOT NULL DEFAULT 'done';
    ALTER TABLE security_scans ADD COLUMN finished_at REAL;
    ALTER TABLE security_scans ADD COLUMN error TEXT;
    ALTER TABLE scan_files ADD COLUMN risk_score INTEGER;
    CREATE INDEX security_scans_by_repo ON security_scans (repo_id);
    CREATE INDEX security_scans_by_status ON security_scans (status);
    CREATE TABLE payloads (
        payload_id INTEGER PRIMARY KEY,
        scan_id TEXT NOT NULL REFERENCES security_scans ON DELETE CASCADE,
        path TEXT NOT NULL,
        line INTEGER NOT NULL,
        rule TEXT NOT NULL,
        kind TEXT NOT NULL,
        encoding TEXT,
        severity TEXT NOT NULL,
        preview TEXT NOT NULL
    );
    CREATE INDEX payloads_by_scan ON payloads (scan_id);
    """,
    # How many alerts a person removed, so a report can say its findings are no longer complete.
    """
    ALTER TABLE security_scans ADD COLUMN removed_alerts INTEGER NOT NULL DEFAULT 0;
    """,
)

MEMORY = ":memory:"
# The 4th upload clears saved scan data first, so the database stays small on a microSD card.
MAX_SAVED_UPLOADS = 3
_DEFAULT_NAME = "astmaster.db"


def default_db_path() -> str:
    """AST_MASTER_DB, else data/ beside the package, else the user's data folder.

    The last one covers an install where the package's parent folder isn't writable.
    An explicit path never falls back: reports must not land somewhere unexpected.
    """
    configured = os.environ.get("AST_MASTER_DB")
    if configured:
        return configured
    project = Path(__file__).resolve().parent.parent / "data"
    existing = next(p for p in (project, *project.parents) if p.exists())
    if os.access(existing, os.W_OK | os.X_OK):
        return str(project / _DEFAULT_NAME)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "astmaster", _DEFAULT_NAME)


def resolve_db_path(path: str | Path | None) -> str:
    """An absolute path, so a later change of working directory can't move the database."""
    path = default_db_path() if path is None else str(path)
    return path if path == MEMORY else os.path.abspath(os.path.expanduser(path))


class Database:
    """One connection behind a lock.

    The web server starts a thread per request, so per-thread connections would
    mean opening one for every request. Queries here take milliseconds, so
    serializing them costs little and suits a Raspberry Pi.
    """

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = resolve_db_path(path)
        self._lock = threading.RLock()
        try:
            if self.path != MEMORY:
                Path(self.path).parent.mkdir(parents=True, exist_ok=True)
                # Results include snippets of uploaded code, so keep them private.
                os.close(os.open(self.path, os.O_CREAT | os.O_RDWR, 0o600))
            self._connection = sqlite3.connect(self.path, timeout=30, isolation_level=None, check_same_thread=False)
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA journal_mode=WAL")
            self._connection.execute("PRAGMA synchronous=NORMAL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._migrate()
        except (OSError, sqlite3.Error) as error:
            raise DatabaseLocationError(
                f"Can't open the SQLite database at {self.path}: {error}. Check that this user "
                "can write to that file and its folder, or choose another with --db or AST_MASTER_DB."
            ) from error

    def query(self, sql: str, parameters: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._connection.execute(sql, parameters).fetchall()

    def execute(self, sql: str, parameters: tuple = ()) -> int:
        """Run one write in its own transaction. Returns the number of rows changed."""
        with self._lock:
            return self._connection.execute(sql, parameters).rowcount

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                yield self._connection
            except BaseException:
                self._connection.execute("ROLLBACK")
                raise
            self._connection.execute("COMMIT")

    def _migrate(self) -> None:
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            for number, script in enumerate(MIGRATIONS[version:], version + 1):
                for statement in script.split(";"):
                    if statement.strip():
                        connection.execute(statement)
                connection.execute(f"PRAGMA user_version={number}")

    def compact(self) -> None:
        """Give freed space back to the disk. Best effort: the data is already deleted."""
        with self._lock:
            try:
                self._connection.execute("VACUUM")
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
            except sqlite3.Error:
                pass

    def close(self) -> None:
        with self._lock:
            self._connection.close()


@dataclass(slots=True)
class AnalysisRecord:
    record_id: str
    filename: str
    created_at: float
    result: AnalysisResult
    transformed_source: str | None


class AnalysisRepository:
    """File analyses and their templates."""

    def __init__(self, database: Database, max_records: int = 1000) -> None:
        self._db = database
        self._max_records = max_records
        self._template_cache: OrderedDict[str, Template] = OrderedDict()
        self._cache_lock = threading.Lock()

    def save(self, filename: str, result: AnalysisResult) -> AnalysisRecord:
        record = AnalysisRecord(secrets.token_urlsafe(9), filename, time.time(), result, result.transformed_source)
        issues = [asdict(i) for i in result.issues]
        with self._db.transaction() as connection:
            connection.execute(
                "INSERT INTO analyses VALUES (?, ?, ?, ?, ?, ?, ?)",
                (record.record_id, filename, record.created_at, result.feasible,
                 json.dumps(result.scan.to_dict()), json.dumps(issues), record.transformed_source),
            )
            for template in result.templates:
                data = template.to_dict()
                connection.execute(
                    "INSERT OR IGNORE INTO templates VALUES (?, ?, ?)",
                    (data["template_id"], data["target"], data["source"]),
                )
                connection.execute(
                    "INSERT INTO analysis_templates VALUES (?, ?, ?)",
                    (record.record_id, data["template_id"], json.dumps(data["sites"])),
                )
            connection.execute(
                "DELETE FROM analyses WHERE analysis_id NOT IN "
                "(SELECT analysis_id FROM analyses ORDER BY created_at DESC LIMIT ?)",
                (self._max_records,),
            )
            connection.execute(
                "DELETE FROM templates WHERE template_id NOT IN (SELECT template_id FROM analysis_templates)"
            )
        return record

    def get(self, record_id: str) -> AnalysisRecord | None:
        rows = self._db.query("SELECT * FROM analyses WHERE analysis_id = ?", (record_id,))
        if not rows:
            return None
        row = rows[0]
        templates = [
            Template.from_dict({
                "template_id": t["template_id"], "target": t["target"], "source": t["source"],
                "sites": json.loads(t["sites_json"]),
            })
            for t in self._db.query(
                "SELECT t.template_id, t.target, t.source, a.sites_json FROM analysis_templates a "
                "JOIN templates t USING (template_id) WHERE a.analysis_id = ?",
                (record_id,),
            )
        ]
        issues = [
            Issue(Severity(i["severity"]), i["code"], i["message"], i["lineno"])
            for i in json.loads(row["issues_json"])
        ]
        scan = ScanResult.from_dict(json.loads(row["scan_json"]))
        result = AnalysisResult(row["filename"], scan, issues, templates)
        return AnalysisRecord(record_id, row["filename"], row["created_at"], result, row["transformed_source"])

    def get_template(self, template_id: str) -> Template | None:
        # Ids are content hashes, so a cached template can never be stale.
        with self._cache_lock:
            template = self._template_cache.get(template_id)
            if template is not None:
                self._template_cache.move_to_end(template_id)
                return template
        rows = self._db.query("SELECT target, source FROM templates WHERE template_id = ?", (template_id,))
        if not rows:
            return None
        template = Template.from_dict({
            "template_id": template_id, "target": rows[0]["target"], "source": rows[0]["source"], "sites": [],
        })
        with self._cache_lock:
            self._template_cache[template_id] = template
            while len(self._template_cache) > 256:
                self._template_cache.popitem(last=False)
        return template


class TaskRepository:
    """Task state survives a restart of the Master."""

    def __init__(self, database: Database, max_tasks: int = 10000) -> None:
        self._db = database
        self._max_tasks = max_tasks

    def create(self, task_id: str, template_id: str, args_repr: str, kwargs_repr: str) -> None:
        with self._db.transaction() as connection:
            connection.execute(
                "INSERT INTO tasks (task_id, template_id, status, args_repr, kwargs_repr, submitted_at) "
                "VALUES (?, ?, 'queued', ?, ?, ?)",
                (task_id, template_id, args_repr, kwargs_repr, time.time()),
            )
            connection.execute(
                "DELETE FROM tasks WHERE status IN ('done', 'failed') AND task_id NOT IN "
                "(SELECT task_id FROM tasks ORDER BY submitted_at DESC LIMIT ?)",
                (self._max_tasks,),
            )

    def mark_running(self, task_id: str) -> None:
        self._db.execute("UPDATE tasks SET status = 'running' WHERE task_id = ?", (task_id,))

    def finish(self, task_id: str, status: str, reply: dict) -> None:
        self._db.execute(
            "UPDATE tasks SET status = ?, reply_json = ?, finished_at = ? WHERE task_id = ?",
            (status, json.dumps(reply), time.time(), task_id),
        )

    def get(self, task_id: str) -> dict | None:
        rows = self._db.query("SELECT status, reply_json FROM tasks WHERE task_id = ?", (task_id,))
        return {"status": rows[0]["status"], **json.loads(rows[0]["reply_json"])} if rows else None

    def fail_interrupted(self) -> int:
        """At startup: tasks that were in flight when the Master stopped can't finish."""
        reply = json.dumps({"error": "the master restarted while this task was running"})
        return self._db.execute(
            "UPDATE tasks SET status = 'failed', reply_json = ?, finished_at = ? WHERE status IN ('queued', 'running')",
            (reply, time.time()),
        )


class SignalCache:
    """Scan results by content hash. Unlike mtime, a hash can't be spoofed."""

    def __init__(self, database: Database, max_entries: int = 500000) -> None:
        self._db = database
        self._max_entries = max_entries

    def get_many(self, keys: Iterable[tuple[str, str]], rules_version: int) -> dict[tuple[str, str], FileSignals]:
        wanted = list(keys)
        found: dict[tuple[str, str], FileSignals] = {}
        for start in range(0, len(wanted), 400):
            hashes = list({sha for sha, _ in wanted[start:start + 400]})
            marks = ",".join("?" * len(hashes))
            rows = self._db.query(
                f"SELECT sha256, handler, signals_json FROM signal_cache "
                f"WHERE rules_version = ? AND sha256 IN ({marks})",
                (rules_version, *hashes),
            )
            batch = set(wanted[start:start + 400])
            for row in rows:
                key = (row["sha256"], row["handler"])
                if key in batch:
                    found[key] = FileSignals.from_dict(json.loads(row["signals_json"]))
        return found

    def put_many(self, entries: Iterable[tuple[str, str, FileSignals]], rules_version: int) -> None:
        rows = [(sha, handler, rules_version, json.dumps(signals.to_dict())) for sha, handler, signals in entries]
        if not rows:
            return
        with self._db.transaction() as connection:
            connection.executemany("INSERT OR REPLACE INTO signal_cache VALUES (?, ?, ?, ?)", rows)
            connection.execute("DELETE FROM signal_cache WHERE rules_version != ?", (rules_version,))
            count = connection.execute("SELECT COUNT(*) FROM signal_cache").fetchone()[0]
            if count > self._max_entries:
                connection.execute("DELETE FROM signal_cache")


class ScanRunning(Exception):
    """A running scan is still writing its rows, so they can't be removed yet."""


class ScanRepository:
    """Security scan reports."""

    def __init__(self, database: Database, max_scans: int = 1000, max_uploads: int = MAX_SAVED_UPLOADS) -> None:
        self._db = database
        self._max_scans = max_scans
        self._max_uploads = max_uploads

    def _reset_if_upload_limit_reached(self) -> bool:
        """Clear all scan data once the upload limit is reached. Signatures stay, because Phase 3 needs them.

        A running scan keeps its rows, because it's still writing to them.
        """
        with self._db.transaction() as connection:
            saved = connection.execute(
                "SELECT COUNT(*) FROM security_scans WHERE source = 'upload' AND status != 'running'"
            ).fetchone()[0]
            if saved < self._max_uploads:
                return False
            connection.execute("DELETE FROM security_scans WHERE status != 'running'")
            connection.execute(
                "DELETE FROM repositories WHERE repo_id NOT IN "
                "(SELECT repo_id FROM security_scans WHERE repo_id IS NOT NULL)"
            )
            connection.execute("DELETE FROM signal_cache")
        return True

    def begin(self, scan_id: str, name: str, source: str, root: str, created_at: float, rules_version: int) -> None:
        """Record the scan before any work, so a crash still leaves a trace of it."""
        if source == "upload" and self._reset_if_upload_limit_reached():
            self._db.compact()
        with self._db.transaction() as connection:
            connection.execute(
                "INSERT INTO repositories (name, source, root, first_seen, last_scanned) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT (source, root) DO UPDATE SET name = excluded.name, last_scanned = excluded.last_scanned",
                (name, source, root, created_at, created_at),
            )
            repo_id = connection.execute(
                "SELECT repo_id FROM repositories WHERE source = ? AND root = ?", (source, root)
            ).fetchone()[0]
            connection.execute(
                "INSERT INTO security_scans (scan_id, name, source, created_at, verdict, rules_version, stats_json, "
                "repo_id, status, stage) VALUES (?, ?, ?, ?, 'PENDING', ?, '{}', ?, 'running', 'walking')",
                (scan_id, name, source, created_at, rules_version, repo_id),
            )

    def record_files(self, scan_id: str, files: list[dict]) -> None:
        """Log files as the walk reaches them. Later writes for a path replace its row."""
        with self._db.transaction() as connection:
            self._write_files(connection, scan_id, files)

    def checkpoint(self, scan_id: str, stage: str, files: list[dict], findings: list[Finding]) -> None:
        """Log results so far. They're provisional until finish(), which replaces them."""
        with self._db.transaction() as connection:
            connection.execute("UPDATE security_scans SET stage = ? WHERE scan_id = ?", (stage, scan_id))
            self._write_files(connection, scan_id, files)
            self._write_findings(connection, scan_id, findings)

    def finish(self, report) -> None:
        with self._db.transaction() as connection:
            connection.execute(
                "UPDATE security_scans SET verdict = ?, risk_score = ?, stats_json = ?, status = 'complete', "
                "stage = 'done', finished_at = ?, error = NULL WHERE scan_id = ?",
                (report.verdict, report.risk_score, json.dumps(report.stats), time.time(), report.scan_id),
            )
            self._write_files(connection, report.scan_id, report.files)
            self._write_findings(connection, report.scan_id, report.findings)
            connection.execute(
                "UPDATE repositories SET last_verdict = ?, last_risk_score = ? WHERE repo_id = "
                "(SELECT repo_id FROM security_scans WHERE scan_id = ?)",
                (report.verdict, report.risk_score, report.scan_id),
            )
            connection.execute(
                "DELETE FROM security_scans WHERE scan_id NOT IN "
                "(SELECT scan_id FROM security_scans ORDER BY created_at DESC LIMIT ?)",
                (self._max_scans,),
            )
            connection.execute(
                "DELETE FROM repositories WHERE repo_id NOT IN "
                "(SELECT repo_id FROM security_scans WHERE repo_id IS NOT NULL)"
            )

    def fail(self, scan_id: str, error: str) -> None:
        """Best effort: the scan's own exception is what the caller needs to see."""
        try:
            self._db.execute(
                "UPDATE security_scans SET status = 'failed', verdict = 'UNKNOWN', finished_at = ?, error = ? "
                "WHERE scan_id = ?",
                (time.time(), error[:1000], scan_id),
            )
        except sqlite3.Error:
            pass

    def fail_interrupted(self) -> int:
        """At server startup: a scan still marked running was cut off by a stop or crash.

        A command line scan running at that moment gets marked too, and finish() corrects it.
        """
        return self._db.execute(
            "UPDATE security_scans SET status = 'interrupted', verdict = 'UNKNOWN', finished_at = ?, "
            "error = 'the server restarted while this scan was running' WHERE status = 'running'",
            (time.time(),),
        )

    @staticmethod
    def _write_files(connection: sqlite3.Connection, scan_id: str, files: list[dict]) -> None:
        connection.executemany(
            "INSERT OR REPLACE INTO scan_files (scan_id, path, sha256, size, status, worst_severity, thread_count, "
            "parallel_feasible, phase1, phase1_reasons, functions, loops, cluster, nearest_signature, risk_score) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, f["path"], f["sha256"], f["size"], f["status"], f["worst_severity"],
              f["thread_count"], f["parallel_feasible"], f["phase1"], f["phase1_reasons"], f["functions"],
              f["loops"], f["cluster"], f["nearest_signature"], f["risk_score"]) for f in files],
        )

    @staticmethod
    def _write_findings(connection: sqlite3.Connection, scan_id: str, findings: list[Finding]) -> None:
        connection.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
        connection.execute("DELETE FROM payloads WHERE scan_id = ?", (scan_id,))
        connection.executemany(
            "INSERT INTO findings (scan_id, path, rule, severity, context, line, message, detail, snippet) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, f.path, f.rule, f.severity, f.context, f.line, f.message, f.detail, f.snippet)
             for f in findings],
        )
        payloads = ((f, payload_fields(f)) for f in findings)
        connection.executemany(
            "INSERT INTO payloads (scan_id, path, line, rule, kind, encoding, severity, preview) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [(scan_id, f.path, f.line, f.rule, *fields[:2], f.severity, fields[2])
             for f, fields in payloads if fields],
        )

    def get(self, scan_id: str) -> dict | None:
        rows = self._db.query("SELECT * FROM security_scans WHERE scan_id = ? AND status = 'complete'", (scan_id,))
        if not rows:
            return None
        row = rows[0]
        findings = [
            Finding(r["rule"], r["severity"], r["context"], r["path"], r["line"], r["message"], r["detail"], r["snippet"])
            for r in self._db.query("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        ]
        files = [dict(r) for r in self._db.query("SELECT * FROM scan_files WHERE scan_id = ? ORDER BY path", (scan_id,))]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: (order[f.severity], f.path, f.line))
        return {
            "scan_id": scan_id, "name": row["name"], "source": row["source"], "created_at": row["created_at"],
            "verdict": row["verdict"], "risk_score": row["risk_score"], "rules_version": row["rules_version"],
            "removed_alerts": row["removed_alerts"],
            "stats": json.loads(row["stats_json"]), "findings": findings, "files": files,
        }

    def dashboard(self, scan_limit: int = 25, repo_limit: int = 50, payload_limit: int = 300) -> dict:
        """Everything the live dashboard shows, read fresh from the database.

        Comparison and payloads use each repository's latest finished scan, so scanning
        the same folder twice doesn't count its payloads twice.
        """
        latest = (
            "WITH latest AS (SELECT repo_id, scan_id, created_at, finished_at FROM ("
            "SELECT repo_id, scan_id, created_at, finished_at, "
            "ROW_NUMBER() OVER (PARTITION BY repo_id ORDER BY created_at DESC) AS position "
            "FROM security_scans WHERE status = 'complete' AND repo_id IS NOT NULL) WHERE position = 1) "
        )
        repositories = [dict(r) for r in self._db.query(
            latest + "SELECT r.repo_id, r.name, r.source, r.root, r.last_verdict, r.last_risk_score, "
            "l.scan_id, l.finished_at, "
            "(SELECT COUNT(*) FROM security_scans s WHERE s.repo_id = r.repo_id AND s.status = 'complete') AS scans, "
            "(SELECT COUNT(*) FROM scan_files f WHERE f.scan_id = l.scan_id) AS files, "
            "(SELECT COUNT(*) FROM payloads p WHERE p.scan_id = l.scan_id) AS payloads "
            "FROM repositories r LEFT JOIN latest l USING (repo_id) "
            "ORDER BY r.last_risk_score IS NULL, r.last_risk_score DESC, r.last_scanned DESC LIMIT ?",
            (repo_limit,),
        )]
        severities: dict[tuple[str, str], int] = {
            (r["scan_id"], r["severity"]): r["total"] for r in self._db.query(
                latest + "SELECT f.scan_id, f.severity, COUNT(*) AS total FROM findings f "
                "JOIN latest USING (scan_id) GROUP BY f.scan_id, f.severity"
            )
        }
        for repository in repositories:
            for severity in ("critical", "high", "medium", "low"):
                repository[severity] = severities.get((repository["scan_id"], severity), 0)
        payload_filter = (
            "FROM payloads p JOIN latest USING (scan_id) JOIN security_scans s USING (scan_id) "
        )
        payloads = [dict(r) for r in self._db.query(
            latest + "SELECT p.payload_id, s.name AS repository, p.scan_id, p.path, p.line, p.rule, p.kind, p.encoding, "
            "p.severity, p.preview " + payload_filter +
            "ORDER BY CASE p.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, "
            "s.created_at DESC, p.path, p.line LIMIT ?",
            (payload_limit,),
        )]
        counts = self._db.query(
            latest + "SELECT COUNT(*) AS total, COALESCE(SUM(p.severity = 'critical'), 0) AS critical " + payload_filter
        )[0]
        verdicts = {r["verdict"]: r["total"] for r in self._db.query(
            "SELECT verdict, COUNT(*) AS total FROM security_scans WHERE status = 'complete' GROUP BY verdict"
        )}
        scans = [dict(r) for r in self._db.query(
            "SELECT s.scan_id, s.name, s.source, s.status, s.stage, s.verdict, s.risk_score, s.created_at, "
            "s.finished_at, s.error, s.removed_alerts, "
            "(SELECT COUNT(*) FROM scan_files f WHERE f.scan_id = s.scan_id) AS files, "
            "(SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.scan_id) AS findings, "
            "(SELECT COUNT(*) FROM payloads p WHERE p.scan_id = s.scan_id) AS payloads "
            "FROM security_scans s ORDER BY s.created_at DESC LIMIT ?",
            (scan_limit,),
        )]
        repository_total = self._db.query("SELECT COUNT(*) FROM repositories")[0][0]
        return {
            "now": time.time(),
            "summary": {
                "repositories": repository_total,
                "scans": sum(verdicts.values()),
                "malicious": verdicts.get("MALICIOUS", 0),
                "suspicious": verdicts.get("SUSPICIOUS", 0),
                "safe": verdicts.get("SAFE", 0),
                "critical_payloads": counts["critical"],
            },
            "repositories": repositories,
            "payloads": payloads,
            "payloads_total": counts["total"],
            "scans": scans,
        }

    # ---- Removing, at a person's request ------------------------------------

    def remove_payload(self, payload_id: int) -> bool:
        """Delete one alert and the finding behind it. The scan's verdict is what it found, so it stays."""
        with self._db.transaction() as connection:
            row = connection.execute(
                "SELECT p.scan_id, p.path, p.line, p.rule, s.status FROM payloads p JOIN security_scans s USING (scan_id) "
                "WHERE p.payload_id = ?", (payload_id,),
            ).fetchone()
            if row is None:
                return False
            if row["status"] == "running":
                raise ScanRunning
            key = (row["scan_id"], row["path"], row["line"], row["rule"])
            where = "WHERE scan_id = ? AND path = ? AND line = ? AND rule = ?"
            connection.execute(f"DELETE FROM payloads {where}", key)
            connection.execute(f"DELETE FROM findings {where}", key)
            connection.execute(
                "UPDATE security_scans SET removed_alerts = removed_alerts + 1 WHERE scan_id = ?", (row["scan_id"],)
            )
            return True

    def remove_scan(self, scan_id: str) -> bool:
        """Delete a scan with its files, findings and payloads, and correct its repository's latest result."""
        with self._db.transaction() as connection:
            row = connection.execute(
                "SELECT repo_id, status FROM security_scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            if row is None:
                return False
            if row["status"] == "running":
                raise ScanRunning
            connection.execute("DELETE FROM security_scans WHERE scan_id = ?", (scan_id,))
            if row["repo_id"] is not None:
                self._refresh_repository(connection, row["repo_id"])
            return True

    def remove_repository(self, repo_id: int) -> bool:
        """Delete a repository and every scan of it."""
        with self._db.transaction() as connection:
            if connection.execute("SELECT 1 FROM repositories WHERE repo_id = ?", (repo_id,)).fetchone() is None:
                return False
            if connection.execute(
                "SELECT 1 FROM security_scans WHERE repo_id = ? AND status = 'running'", (repo_id,)
            ).fetchone():
                raise ScanRunning
            connection.execute("DELETE FROM security_scans WHERE repo_id = ?", (repo_id,))
            connection.execute("DELETE FROM repositories WHERE repo_id = ?", (repo_id,))
            return True

    @staticmethod
    def _refresh_repository(connection: sqlite3.Connection, repo_id: int) -> None:
        if connection.execute("SELECT 1 FROM security_scans WHERE repo_id = ?", (repo_id,)).fetchone() is None:
            connection.execute("DELETE FROM repositories WHERE repo_id = ?", (repo_id,))
            return
        latest = connection.execute(
            "SELECT verdict, risk_score FROM security_scans WHERE repo_id = ? AND status = 'complete' "
            "ORDER BY created_at DESC LIMIT 1", (repo_id,),
        ).fetchone()
        connection.execute(
            "UPDATE repositories SET last_verdict = ?, last_risk_score = ? WHERE repo_id = ?",
            (latest["verdict"] if latest else None, latest["risk_score"] if latest else None, repo_id),
        )

    def recent(self, limit: int = 50) -> list[dict]:
        rows = self._db.query(
            "SELECT scan_id, name, source, created_at, verdict, risk_score FROM security_scans "
            "WHERE status = 'complete' ORDER BY created_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in rows]


class SignatureRepository:
    """Reference vectors for Phase 3: known attack patterns and benign code."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def replace_all(self, rows: list[dict], feature_version: int) -> None:
        with self._db.transaction() as connection:
            connection.execute("DELETE FROM signatures")
            connection.executemany(
                "INSERT INTO signatures (name, label, category, feature_version, vector_json) VALUES (?, ?, ?, ?, ?)",
                [(r["name"], r["label"], r["category"], feature_version, json.dumps(r["vector"])) for r in rows],
            )

    def seed_if_empty(self, seed_path: str | Path, feature_version: int) -> None:
        rows = self._db.query("SELECT 1 FROM signatures WHERE feature_version = ? LIMIT 1", (feature_version,))
        if rows or not Path(seed_path).exists():
            return
        seed = json.loads(Path(seed_path).read_text(encoding="utf-8"))
        if seed["feature_version"] == feature_version:
            self.replace_all(seed["rows"], feature_version)

    def load(self, feature_version: int) -> list[dict]:
        return [
            {"name": r["name"], "label": r["label"], "category": r["category"], "vector": json.loads(r["vector_json"])}
            for r in self._db.query("SELECT * FROM signatures WHERE feature_version = ?", (feature_version,))
        ]

    def counts(self) -> dict[str, int]:
        return {r["label"]: r[1] for r in self._db.query("SELECT label, COUNT(*) FROM signatures GROUP BY label")}
