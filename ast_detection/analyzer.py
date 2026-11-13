"""Package-level analysis: built-in extractor + AST Master -> one feature vector.

The output contract (``schema_version`` 1) consumed by the AI engine::

    {
      "schema_version": 1,
      "package": "<name>",
      "backend": {...astmaster info...},
      "features": {"ast_*": float, "am_*": float},      # model inputs
      "feature_digest": "<sha256 of canonical features JSON>",
      "static_risk": {"score": 0..1, "source": "astmaster"|"builtin", "verdict": ...},
      "findings": [...],          # astmaster findings (capped)
      "files": [...]              # per-file summary
    }
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Mapping
from typing import Any

from ast_detection import FEATURE_SCHEMA_VERSION, __version__
from ast_detection.extractors import aggregate_package, extract_file_features
from ast_detection.parser import AstMasterParser

#: astmaster rules exposed as individual count features (``am_rule_<name>``).
TRACKED_RULES: tuple[str, ...] = (
    "exec-decoded", "hidden-code", "exec-dynamic", "exec-network", "download-execute", "install-hook",
    "network-call", "exfiltration", "env-exfiltration", "credential-exfiltration", "recon",
    "recon-exfiltration", "secret-path", "secret-env", "persistence", "decoder", "shell-dangerous",
    "shell-dynamic", "obfuscated-name", "obfuscated-sink", "dynamic-import", "raw-ip-url", "silent-sink",
    "opaque-string", "self-delete", "typosquat-dep",
)
_SEVERITIES = ("critical", "high", "medium", "low")
_CONTEXTS = ("install", "import", "runtime")
_VERDICT_LEVEL = {"SAFE": 0.0, "SUSPICIOUS": 1.0, "MALICIOUS": 2.0}
_PYTHON_SUFFIXES = (".py", ".pyw")
MAX_FINDINGS_RETURNED = 50
MAX_RISKY_NODES_RETURNED = 300
_NODE_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def astmaster_feature_names() -> list[str]:
    """Names of all ``am_*`` features, in a fixed order."""
    return (
        ["am_available", "am_risk_score", "am_verdict_level", "am_files_scanned"]
        + [f"am_sev_{s}" for s in _SEVERITIES]
        + [f"am_ctx_{c}" for c in _CONTEXTS]
        + ["am_functions", "am_loops", "am_threads", "am_max_loop_depth"]
        + [f"am_rule_{r.replace('-', '_')}" for r in TRACKED_RULES]
    )


def feature_digest(features: Mapping[str, float]) -> str:
    """SHA-256 over the canonical JSON encoding of a feature mapping."""
    payload = json.dumps({k: round(float(v), 6) for k, v in sorted(features.items())}, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class PackageAnalyzer:
    """Analyse a package's files into a model-ready feature vector.

    Args:
        parser: AST Master adapter; created (with discovery) if omitted.
    """

    def __init__(self, parser: AstMasterParser | None = None) -> None:
        self.parser = parser or AstMasterParser()

    def analyze(self, name: str, files: Mapping[str, str | bytes]) -> dict[str, Any]:
        """Analyse ``files`` (relative path -> source) of package ``name``. Never executes code."""
        started = time.perf_counter()
        builtin_files = []
        am_results = []
        file_summaries: list[dict[str, Any]] = []
        for path in sorted(files):
            raw = files[path]
            data = raw.encode("utf-8", "surrogatepass") if isinstance(raw, str) else bytes(raw)
            summary: dict[str, Any] = {"path": path, "bytes": len(data)}
            if path.lower().endswith(_PYTHON_SUFFIXES):
                ff = extract_file_features(path, data)
                builtin_files.append(ff)
                summary["parse_error"] = bool(ff.values["parse_error"])
                summary["risky_nodes"] = len(ff.nodes)
            am = self.parser.analyze_file(path, data)
            if am is not None:
                am_results.append(am)
                summary.update(astmaster_status=am.status, kind=am.kind, findings=len(am.findings))
            file_summaries.append(summary)

        features = aggregate_package(builtin_files)
        am_features, findings, am_summary = self._astmaster_features(am_results)
        features.update(am_features)

        if self.parser.available:
            score = float(am_summary["risk_score"]) / 100.0
            static = {"score": score, "source": "astmaster", "verdict": am_summary["verdict"]}
        else:
            score = features["ast_builtin_risk"]
            verdict = "MALICIOUS" if score >= 0.8 else "SUSPICIOUS" if score >= 0.4 else "SAFE"
            static = {"score": score, "source": "builtin", "verdict": verdict}
        static["builtin_risk"] = features["ast_builtin_risk"]
        static["astmaster_risk_score"] = am_summary["risk_score"]

        return {
            "schema_version": FEATURE_SCHEMA_VERSION,
            "service_version": __version__,
            "package": name,
            "backend": self.parser.backend_info(),
            "features": features,
            "feature_digest": feature_digest(features),
            "static_risk": static,
            "findings": [
                {"rule": f.rule, "severity": f.severity, "context": f.context, "path": f.path,
                 "line": f.line, "message": f.message}
                for f in sorted(findings, key=lambda f: _SEVERITIES.index(f.severity) if f.severity in _SEVERITIES else 9)
            ][:MAX_FINDINGS_RETURNED],
            "files": file_summaries,
            # Location-level evidence for analysts/dashboards. Not a model input (not in the digest).
            "risky_nodes": [
                n.to_dict() for n in sorted((n for f in builtin_files for n in f.nodes),
                                            key=lambda n: (_NODE_RANK[n.severity], n.path, n.line))
            ][:MAX_RISKY_NODES_RETURNED],
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
        }

    def _astmaster_features(self, results: list[Any]) -> tuple[dict[str, float], list[Any], dict[str, Any]]:
        feats = dict.fromkeys(astmaster_feature_names(), 0.0)
        findings = [f for r in results for f in r.findings]
        summary = self.parser.summarize(findings)
        if not self.parser.available:
            return feats, findings, summary
        feats["am_available"] = 1.0
        feats["am_risk_score"] = float(summary["risk_score"])
        feats["am_verdict_level"] = _VERDICT_LEVEL.get(summary["verdict"], 0.0)
        feats["am_files_scanned"] = float(len(results))
        for f in findings:
            if f.severity in _SEVERITIES:
                feats[f"am_sev_{f.severity}"] += 1
            if f.context in _CONTEXTS:
                feats[f"am_ctx_{f.context}"] += 1
            key = f"am_rule_{f.rule.replace('-', '_')}"
            if key in feats:
                feats[key] += 1
        for r in results:
            s = r.structure
            feats["am_functions"] += s.get("functions", 0)
            feats["am_loops"] += s.get("loops", 0)
            feats["am_threads"] += s.get("threads", 0)
            feats["am_max_loop_depth"] = max(feats["am_max_loop_depth"], float(s.get("max_loop_depth", 0)))
        return feats, findings, summary
