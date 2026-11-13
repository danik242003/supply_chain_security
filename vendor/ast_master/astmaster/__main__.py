"""Command line: python3 -m astmaster {serve,analyze,scan}"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
from dataclasses import asdict
from pathlib import Path

from .models import DatabaseLocationError


def _serve(options: argparse.Namespace) -> int:
    from .web import create_server

    server = create_server(
        options.root, options.host, options.port, options.enable_execution, db_path=options.db, local_only=options.local_only
    )

    def stop(*_: object) -> None:
        # docker stop and systemd send SIGTERM, which would otherwise skip the cleanup below.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    app = server.app
    host, port = server.server_address[:2]
    print(f"Serving {app.root} at http://{host}:{port}/", flush=True)
    print(f"Database: {app.database.path}", flush=True)
    if not app.loopback_only:
        print("WARNING: there is no login. Anyone who can reach this port can browse the target directory.", flush=True)
    if app.executor:
        print("Execution is ON. Tasks run unsandboxed as this user. To run a transformed program:")
        print(f"  AST_MASTER_URL=http://{host}:{port} AST_MASTER_TOKEN={app.token} python3 transformed.py", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        app.scanner.close()
        app.security.close()
        if app.executor:
            app.executor.close()
        app.database.close()
    return 0


def _analyze(options: argparse.Namespace) -> int:
    from .pipeline import analyze_source

    result = analyze_source(Path(options.file).read_bytes(), options.file)
    if options.json:
        print(json.dumps({
            "feasible": result.feasible,
            "issues": [asdict(i) for i in result.issues],
            "scan": result.scan.to_dict(),
            "templates": [t.to_dict() for t in result.templates],
        }, indent=2))
    else:
        print("Suitable for parallel execution" if result.feasible else "Not suitable for parallel execution")
        for issue in result.issues:
            print(f"  {issue.severity.value} line {issue.lineno or '-'} [{issue.code}]: {issue.message}")
        print(f"  {len(result.templates)} template(s)")
    if options.output and result.transformed_source:
        Path(options.output).write_text(result.transformed_source, encoding="utf-8")
        print(f"Wrote {options.output}")
    return 0 if result.feasible else 1


def _scan(options: argparse.Namespace) -> int:
    from .discovery import TreeScanner

    scanner = TreeScanner(options.workers)
    try:
        tree = scanner.scan(options.directory, threads_only=options.threads_only)
    finally:
        scanner.close()
    for report in tree.reports:
        if report.has_threads:
            verdict = "suitable" if report.feasible else "not suitable"
            print(f"{report.path}: {verdict} ({len(report.scan.threads)} threads)")
    print(json.dumps(asdict(tree.stats)))
    return 0


def _security(options: argparse.Namespace) -> int:
    from .db import Database, ScanRepository, SignalCache, SignatureRepository
    from .secscan import SecurityScanner

    database = Database(options.db)
    scanner = SecurityScanner(SignalCache(database), ScanRepository(database), SignatureRepository(database), options.workers)
    try:
        report = scanner.scan_directory(options.directory)
    finally:
        scanner.close()
        database.close()
    if options.json:
        print(json.dumps({
            "scan_id": report.scan_id, "verdict": report.verdict, "risk_score": report.risk_score,
            "stats": report.stats, "findings": [asdict(f) for f in report.findings],
        }, indent=2))
    else:
        print(f"{report.verdict} (risk {report.risk_score}/100): {report.stats['scanned']} files in {report.stats['seconds'] * 1000:.0f} ms")
        for finding in report.findings:
            if finding.severity != "low" or options.all:
                print(f"  {finding.severity:8} {finding.context:10} {finding.path}:{finding.line} {finding.rule}: {finding.message}")
    return {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}[report.verdict]


def main() -> int:
    db_help = "SQLite database file, or :memory: (default: AST_MASTER_DB, else data/astmaster.db)"
    parser = argparse.ArgumentParser(prog="astmaster")
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the web interface")
    serve.add_argument("--root", default=os.path.expanduser("~/Desktop"), help="directory the explorer shows")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument(
        "--local-only", action="store_true",
        help="keep the localhost Host check on a non-loopback bind, for a container whose port is published on 127.0.0.1",
    )
    serve.add_argument("--enable-execution", action="store_true", help="accept tasks from transformed programs")
    serve.add_argument("--db", help=db_help)
    serve.set_defaults(run=_serve)

    analyze = commands.add_parser("analyze", help="analyze one Python file")
    analyze.add_argument("file")
    analyze.add_argument("-o", "--output", help="write the transformed program here")
    analyze.add_argument("--json", action="store_true")
    analyze.set_defaults(run=_analyze)

    scan = commands.add_parser("scan", help="scan a directory tree")
    scan.add_argument("directory")
    scan.add_argument("--threads-only", action="store_true", help="skip parsing files with no Thread in them")
    scan.add_argument("--workers", type=int)
    scan.set_defaults(run=_scan)

    security = commands.add_parser("security", help="check a folder for supply chain attack indicators")
    security.add_argument("directory")
    security.add_argument("--db", help=db_help)
    security.add_argument("--json", action="store_true")
    security.add_argument("--all", action="store_true", help="include low severity notes")
    security.add_argument("--workers", type=int)
    security.set_defaults(run=_security)

    options = parser.parse_args()
    try:
        return options.run(options)
    except DatabaseLocationError as error:
        # Not 0, 1 or 2: those are the verdicts of the security command.
        print(f"astmaster: {error}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
