"""Offline inference: package -> AST service -> ML models -> structured JSON risk report.

Usage::

    python -m ai_engine.predict --samples                          # bundled mock payloads
    python -m ai_engine.predict --package path/to/pkg [--package other_pkg]
    python -m ai_engine.predict --package setup.py --metadata meta.json
    python -m ai_engine.predict --bundle packages.json             # {"packages": [{name, files, metadata}]}
    python -m ai_engine.predict --samples --fail-on high           # CI gate: exit 3
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ai_engine.ast_client import ASTServiceClient
from ai_engine.config import ARTIFACT_DIR, SAMPLES_DIR
from ai_engine.data.loader import load_bundle, load_package_dir, normalize_metadata
from ai_engine.events import EventEmitter
from ai_engine.features.pipeline import build_frame
from ai_engine.models.hybrid_scorer import SEVERITY_ORDER, HybridScorer

logger = logging.getLogger("ai_engine.predict")
EXIT_THRESHOLD_BREACHED = 3


class RiskEngine:
    """Loads trained artifacts and scores packages through the AST service.

    Args:
        artifact_dir: Directory written by ``train.py``.
        client: AST service client (defaults to ``$AST_SERVICE_URL``).
    """

    def __init__(self, artifact_dir: str | Path = ARTIFACT_DIR, client: ASTServiceClient | None = None,
                 emitter: EventEmitter | None = None) -> None:
        self.scorer = HybridScorer.load(artifact_dir)
        self.client = client or ASTServiceClient()
        self.emitter = emitter or EventEmitter("ai_engine")

    def assess(self, packages: list[dict[str, Any]], top_k: int = 5) -> list[dict[str, Any]]:
        """Score ``[{"name", "files", "metadata"?, "request_id"?}]`` and return one report per package.

        Each package gets a ``request_id`` (generated if absent) that correlates the AST
        service's parse events with this engine's assessment events on the dashboard.
        """
        started = time.perf_counter()
        packages = [{**p, "request_id": p.get("request_id") or uuid.uuid4().hex} for p in packages]
        for p in packages:
            self.emitter.emit("ai.assess.started", request_id=p["request_id"], package=p["name"],
                              n_files=len(p["files"]), metadata=p.get("metadata"))
        try:
            ast_results = self.client.analyze_batch(packages)
            frame = build_frame(packages, ast_results)
            reports = self.scorer.build_reports(frame, ast_results, top_k=top_k)
        except Exception as exc:
            for p in packages:
                self.emitter.emit("ai.assess.failed", request_id=p["request_id"], package=p["name"],
                                  error=f"{type(exc).__name__}: {exc}"[:500])
            raise
        elapsed = round((time.perf_counter() - started) * 1000, 2)
        for pkg, rep in zip(packages, reports):
            rep["request_id"] = pkg["request_id"]
            rep["duration_ms"] = elapsed
            if "source_path" in pkg:
                rep["source_path"] = pkg["source_path"]
            self.emitter.emit("ai.assess.completed", request_id=pkg["request_id"], package=pkg["name"], report=rep)
        return reports

    def build_output(self, reports: list[dict[str, Any]]) -> dict[str, Any]:
        """Wrap reports with model info and a summary."""
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "model": {"trained_at": self.scorer.metadata.get("created_at"),
                      "ast_backend": self.scorer.metadata.get("ast_backend"),
                      "decision_threshold": self.scorer.config.decision_threshold},
            "summary": {"packages": len(reports), "flagged": sum(r["flagged"] for r in reports),
                        "by_severity": dict(Counter(r["severity"] for r in reports)),
                        "all_verifications_passed": all(r["verification"]["passed"] for r in reports)},
            "reports": reports,
        }


def sample_packages(samples_dir: Path = SAMPLES_DIR) -> list[dict[str, Any]]:
    """Load every package directory under ``samples/``."""
    dirs = sorted(d for d in samples_dir.iterdir() if d.is_dir())
    if not dirs:
        raise FileNotFoundError(f"no sample packages in {samples_dir}")
    return [load_package_dir(d) for d in dirs]


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="Score Python packages with the AST + ML engine.")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--package", action="append", type=Path, help="Package directory or file (repeatable)")
    src.add_argument("--bundle", type=Path, help="JSON bundle of packages")
    src.add_argument("--samples", action="store_true", help="Score the bundled mock payloads")
    ap.add_argument("--metadata", type=Path, help="Registry metadata JSON (single --package only)")
    ap.add_argument("--artifacts", type=Path, default=ARTIFACT_DIR)
    ap.add_argument("--ast-url", help="AST service URL (default $AST_SERVICE_URL)")
    ap.add_argument("--output", type=Path)
    ap.add_argument("--fail-on", choices=[s.lower() for s in SEVERITY_ORDER[1:]])
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")

    if args.samples:
        packages = sample_packages()
    elif args.bundle:
        packages = load_bundle(args.bundle)
    else:
        packages = [load_package_dir(p) for p in args.package]
        if args.metadata:
            if len(packages) != 1:
                ap.error("--metadata requires exactly one --package")
            packages[0]["metadata"] = normalize_metadata(json.loads(args.metadata.read_text()))

    client = ASTServiceClient(args.ast_url)
    client.wait_until_ready(timeout=30)
    engine = RiskEngine(args.artifacts, client)
    output = engine.build_output(engine.assess(packages))
    engine.emitter.flush()
    text = json.dumps(output, indent=2)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
        print(f"report written to {args.output}", file=sys.stderr)
    else:
        print(text)
    for r in output["reports"]:
        print(f"{r['package_name']:<28}{r['severity']:<10}{r['action']:<19}risk={r['risk_score']:.3f} "
              f"type={r['predicted_attack_type']} layers={r['detection_layers']} "
              f"ast_delta={r['ast_influence']['delta']:+.3f} verified={r['verification']['passed']}", file=sys.stderr)
    if args.fail_on:
        bar = SEVERITY_ORDER.index(args.fail_on.upper())
        if any(SEVERITY_ORDER.index(r["severity"]) >= bar for r in output["reports"]):
            return EXIT_THRESHOLD_BREACHED
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
