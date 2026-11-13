"""Hybrid risk scoring and layer verification: AST static score + Random Forest + Isolation Forest.

Fusion (all inputs in [0, 1])::

    s_gated = static_weight * clip((s - static_floor)  / (1 - static_floor),  0, 1)   # AST Master / builtin score
    a_gated =                 clip((a - anomaly_floor) / (1 - anomaly_floor), 0, 1)   # Isolation Forest percentile
    risk    = 1 - (1 - p) * (1 - a_gated) * (1 - s_gated)                            # noisy-OR with RF probability p

Floors are benign quantiles on validation data (false-positive budgets); the
decision/critical thresholds and ``static_weight`` (never 0, so the AST layer
always participates) are tuned to maximise F-beta under a precision floor.

Verification
    * per prediction: the AST block of the model matrix must equal the scaled
      service features, the feature digest must have verified, and
      ``ast_influence`` reports how much risk disappears when the AST layer is
      ablated (AST features -> benign reference, static term removed);
    * globally (:meth:`HybridScorer.verify_layers`): the classifier must rely on AST
      features, ablating the AST layer must hurt detection, ablating the ML layer must
      hurt detection, and the hybrid must be at least as good as static analysis alone.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import platform
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.metrics import f1_score, roc_auc_score

from ai_engine import __version__
from ai_engine.config import BENIGN_LABEL, CRITICAL_ATTACK_TYPES
from ai_engine.features.pipeline import FeaturePipeline
from ai_engine.models.anomaly_detector import AnomalyDetector
from ai_engine.models.threat_classifier import ThreatClassifier

logger = logging.getLogger(__name__)

HMAC_ENV_VAR = "SCS_HMAC_KEY"
MANIFEST_NAME = "manifest.json"
_COMPONENTS = {"pipeline": "feature_pipeline.joblib", "detector": "anomaly_detector.joblib",
               "classifier": "threat_classifier.joblib"}
SEVERITY_ORDER: tuple[str, ...] = ("NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL")
SEVERITY_ACTIONS = {"CRITICAL": "BLOCK", "HIGH": "BLOCK", "MEDIUM": "QUARANTINE_REVIEW", "LOW": "MONITOR", "NONE": "ALLOW"}


class ArtifactIntegrityError(RuntimeError):
    """Model artifacts failed hash/signature verification."""


@dataclass
class HybridConfig:
    """Fusion and decision parameters (see module docstring)."""

    anomaly_floor: float = 0.99
    static_floor: float = 0.3
    static_weight: float = 0.75
    decision_threshold: float = 0.5
    critical_threshold: float = 0.5
    anomaly_fpr_budget: float = 0.01
    static_fpr_budget: float = 0.02
    beta: float = 2.0
    min_precision: float = 0.9
    high_risk: float = 0.75
    critical_risk: float = 0.92
    critical_attack_types: tuple[str, ...] = field(default_factory=lambda: tuple(CRITICAL_ATTACK_TYPES))

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> HybridConfig:
        """Rebuild from :func:`dataclasses.asdict` output."""
        data = dict(data)
        data["critical_attack_types"] = tuple(data.get("critical_attack_types", CRITICAL_ATTACK_TYPES))
        return cls(**data)


@dataclass
class VerificationThresholds:
    """Minimum evidence that both layers contribute (checked after training)."""

    min_ast_importance_share: float = 0.25
    min_ast_ablation_auc_drop: float = 0.005
    min_ml_ablation_f1_drop: float = 0.05
    max_f1_deficit_vs_static: float = 0.03


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class HybridScorer:
    """Orchestrates pipeline, both models, the static AST score and the decision policy."""

    def __init__(self, pipeline: FeaturePipeline, detector: AnomalyDetector, classifier: ThreatClassifier,
                 config: HybridConfig | None = None) -> None:
        self.pipeline = pipeline
        self.detector = detector
        self.classifier = classifier
        self.config = config or HybridConfig()
        self.metadata: dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Core scoring
    # ------------------------------------------------------------------ #
    def _components(self, X: np.ndarray) -> dict[str, np.ndarray]:
        proba = self.classifier.predict_proba(X)
        classes = list(self.classifier.classes_)
        closest, conf = self.classifier.closest_attack(X, proba=proba)
        return {
            "threat_probability": 1.0 - proba[:, classes.index(BENIGN_LABEL)],
            "closest_attack": closest,
            "closest_attack_confidence": conf,
            "anomaly_score": self.detector.score(X),
            "anomaly_raw": self.detector.raw_score(X),
        }

    @staticmethod
    def fuse(p: np.ndarray, a: np.ndarray, s: np.ndarray, closest: np.ndarray, cfg: HybridConfig,
             static_malicious: np.ndarray | None = None, **overrides: float) -> dict[str, np.ndarray]:
        """Vectorised fusion policy; ``overrides`` replace config fields (used during tuning).

        Below the decision threshold, an event is still flagged when the classifier reaches
        ``critical_threshold`` and either (a) its closest family is high-impact (*escalated*) or
        (b) the AST static layer independently rates the code MALICIOUS (*corroborated*).
        """
        c = {**asdict(cfg), **overrides}
        a_g = np.clip((a - c["anomaly_floor"]) / max(1 - c["anomaly_floor"], 1e-9), 0, 1)
        s_g = c["static_weight"] * np.clip((s - c["static_floor"]) / max(1 - c["static_floor"], 1e-9), 0, 1)
        risk = 1 - (1 - p) * (1 - a_g) * (1 - s_g)
        crit_family = np.isin(closest, c["critical_attack_types"])
        below = (p >= c["critical_threshold"]) & (risk < c["decision_threshold"])
        escalated = crit_family & below
        corroborated = (np.zeros(len(p), bool) if static_malicious is None else np.asarray(static_malicious, bool)) & below
        return {"anomaly_component": a_g, "static_component": s_g, "risk_score": risk, "escalated": escalated,
                "corroborated": corroborated, "flagged": (risk >= c["decision_threshold"]) | escalated | corroborated}

    def score_frame(self, frame: pd.DataFrame, with_ablation: bool = True) -> pd.DataFrame:
        """Score a feature frame (from :func:`build_frame`). Adds decisions and verification columns."""
        cfg = self.config
        X = self.pipeline.transform(frame)
        comp = self._components(X)
        s = frame["static_risk"].to_numpy(float)
        static_malicious = (frame["static_verdict"] == "MALICIOUS").to_numpy()
        fused = self.fuse(comp["threat_probability"], comp["anomaly_score"], s, comp["closest_attack"], cfg,
                          static_malicious=static_malicious)
        out = pd.DataFrame({**comp, **fused, "static_risk": s}, index=frame.index)

        p, risk, flagged = out["threat_probability"], out["risk_score"], out["flagged"]
        sup = (p >= cfg.decision_threshold) | out["escalated"] | out["corroborated"]
        anom = out["anomaly_component"] >= cfg.decision_threshold
        stat = (out["static_component"] >= cfg.decision_threshold) | out["corroborated"]
        hits = pd.DataFrame({"static": stat, "supervised": sup, "anomaly": anom})
        out["detection_layers"] = [
            ",".join(k for k, v in row.items() if v) if f else "" for row, f in zip(hits.to_dict("records"), flagged)
        ]
        out.loc[flagged & (out["detection_layers"] == ""), "detection_layers"] = "combined"
        critical_family = np.isin(out["closest_attack"], cfg.critical_attack_types) & sup
        # Escalation backed only by the classifier (metadata-heavy) buys recall with *reviews*: capped at
        # MEDIUM. When the AST layer independently rates the code MALICIOUS, the two layers corroborate
        # each other and the verdict is a block (at least HIGH).
        corroborated = out["corroborated"]
        confident = flagged & ~(out["escalated"] & ~corroborated)
        out["severity"] = np.select(
            [confident & ((risk >= cfg.critical_risk) | critical_family), confident & ((risk >= cfg.high_risk) | corroborated), flagged,
             risk >= cfg.decision_threshold / 2],
            ["CRITICAL", "HIGH", "MEDIUM", "LOW"], default="NONE")
        out["action"] = out["severity"].map(SEVERITY_ACTIONS)
        out["predicted_attack_type"] = np.where(
            ~flagged, BENIGN_LABEL,
            # Name the classifier's closest family whenever it is at least moderately confident.
            np.where(sup | (p >= cfg.critical_threshold), out["closest_attack"],
                     np.where(anom & ~stat, "unknown_anomaly", "static_threat")))

        # --- verification ----------------------------------------------------
        out["ast_in_model_input"] = self.pipeline.ast_columns_reached_model(frame, X)
        out["ast_nonzero_features"] = (frame[self.pipeline.ast_features_].to_numpy(float) != 0).sum(axis=1)
        if with_ablation:
            ablated = self.pipeline.ablate_ast(frame)
            Xa = self.pipeline.transform(ablated)
            ca = self._components(Xa)
            fa = self.fuse(ca["threat_probability"], ca["anomaly_score"], np.zeros_like(s), ca["closest_attack"], cfg)
            out["risk_without_ast"] = fa["risk_score"]
            out["ast_influence"] = out["risk_score"] - fa["risk_score"]
            out["flagged_without_ast"] = fa["flagged"]
        return out

    # ------------------------------------------------------------------ #
    # Calibration
    # ------------------------------------------------------------------ #
    def calibrate(self, frame: pd.DataFrame, y: np.ndarray) -> dict[str, Any]:
        """Set floors from benign quantiles and grid-search thresholds + static weight on validation data."""
        cfg = self.config
        y = np.asarray(y).astype(int)
        comp = self._components(self.pipeline.transform(frame))
        p, a, closest = comp["threat_probability"], comp["anomaly_score"], comp["closest_attack"]
        s = frame["static_risk"].to_numpy(float)
        static_malicious = (frame["static_verdict"] == "MALICIOUS").to_numpy()
        cfg.anomaly_floor = float(np.quantile(a[y == 0], 1 - cfg.anomaly_fpr_budget))
        cfg.static_floor = float(min(np.quantile(s[y == 0], 1 - cfg.static_fpr_budget), 0.95))

        n_pos = max(int(y.sum()), 1)
        b2 = cfg.beta ** 2
        grid: list[tuple[float, float, float, float, float, float, float]] = []  # feasible, fb, prec, rec, w, thr, crit
        for w in (0.25, 0.5, 0.75, 1.0):
            for thr in np.round(np.arange(0.1, 0.951, 0.025), 3):
                for crit in np.round(np.append(np.arange(0.1, thr, 0.05), thr), 3):
                    flagged = self.fuse(p, a, s, closest, cfg, static_malicious, static_weight=w,
                                        decision_threshold=thr, critical_threshold=crit)["flagged"]
                    tp = float(np.sum(flagged & (y == 1)))
                    fp = float(np.sum(flagged & (y == 0)))
                    prec = tp / (tp + fp) if tp + fp else 0.0
                    rec = tp / n_pos
                    fb = (1 + b2) * prec * rec / (b2 * prec + rec) if prec + rec else 0.0
                    grid.append((float(prec >= cfg.min_precision), round(fb, 6), prec, rec, w, float(thr), float(crit)))
        # Many settings tie on cleanly separable validation data. Picking the most extreme tied threshold
        # leaves no margin for real-world inputs, so choose the *middle* of the optimal plateau (max margin),
        # and the largest tied AST weight (the deterministic static layer counts as much as validation allows).
        top = max(g[:2] for g in grid)
        ties = [g for g in grid if g[:2] == top]
        w = max(g[4] for g in ties)
        ties = [g for g in ties if g[4] == w]
        thr = float(np.median(sorted({g[5] for g in ties})))
        thr = min({g[5] for g in ties}, key=lambda t: abs(t - thr))
        crits = sorted(g[6] for g in ties if g[5] == thr)
        crit = crits[len(crits) // 2]
        fb, prec, rec = next((g[1], g[2], g[3]) for g in ties if g[5] == thr and g[6] == crit)
        summary_ties = {"tied_settings": len(ties), "plateau_thresholds": [min(g[5] for g in ties), max(g[5] for g in ties)]}
        cfg.decision_threshold, cfg.critical_threshold, cfg.static_weight = thr, crit, w
        summary = {"anomaly_floor": cfg.anomaly_floor, "static_floor": cfg.static_floor, "static_weight": w,
                   "decision_threshold": thr, "critical_threshold": crit, "val_fbeta": fb,
                   "val_precision": prec, "val_recall": rec, "precision_constraint_met": prec >= cfg.min_precision,
                   **summary_ties}
        logger.info("Hybrid calibration: %s", summary)
        return summary

    # ------------------------------------------------------------------ #
    # Layer verification (global)
    # ------------------------------------------------------------------ #
    def verify_layers(self, frame: pd.DataFrame, y: np.ndarray,
                      thresholds: VerificationThresholds | None = None) -> dict[str, Any]:
        """Prove on labelled data that both the AST layer and the ML layer drive the verdicts."""
        t = thresholds or VerificationThresholds()
        y = np.asarray(y).astype(int)
        scored = self.score_frame(frame, with_ablation=True)
        imp = self.classifier.feature_importances_
        ast_share = float(imp[self.pipeline.ast_indices].sum() / max(imp.sum(), 1e-12))

        auc_full = float(roc_auc_score(y, scored["risk_score"]))
        auc_no_ast = float(roc_auc_score(y, scored["risk_without_ast"]))
        static_pred = (frame["static_verdict"] != "SAFE").to_numpy()
        f1_static = float(f1_score(y, static_pred, zero_division=0))
        f1_hybrid = float(f1_score(y, scored["flagged"], zero_division=0))
        f1_no_ast = float(f1_score(y, scored["flagged_without_ast"], zero_division=0))
        # ML ablation: drop RF + IF outputs, keep only the AST static term, same thresholds.
        cfg = self.config
        zeros = np.zeros(len(frame))
        no_ml = self.fuse(zeros, zeros, frame["static_risk"].to_numpy(float), scored["closest_attack"].to_numpy(), cfg)
        f1_no_ml = float(f1_score(y, no_ml["flagged"], zero_division=0))
        fpr = lambda pred: float(np.mean(np.asarray(pred, bool)[y == 0])) if (y == 0).any() else 0.0  # noqa: E731

        checks = {
            "ast_features_reached_model": bool(scored["ast_in_model_input"].all()),
            "ast_importance_share_ok": ast_share >= t.min_ast_importance_share,
            "ast_ablation_hurts_detection": (auc_full - auc_no_ast) >= t.min_ast_ablation_auc_drop or f1_hybrid > f1_no_ast,
            "ml_ablation_hurts_detection": (f1_hybrid - f1_no_ml) >= t.min_ml_ablation_f1_drop,
            "hybrid_not_worse_than_static": f1_hybrid >= f1_static - t.max_f1_deficit_vs_static,
        }
        result = {
            "passed": all(checks.values()),
            "checks": checks,
            "rf_ast_importance_share": ast_share,
            "hybrid_roc_auc": auc_full,
            "hybrid_roc_auc_without_ast": auc_no_ast,
            "hybrid_f1": f1_hybrid,
            "hybrid_f1_without_ast": f1_no_ast,
            "hybrid_f1_without_ml": f1_no_ml,
            "static_only_f1": f1_static,
            "static_only_fpr": fpr(static_pred),
            "hybrid_fpr": fpr(scored["flagged"]),
            "mean_ast_influence_malicious": float(scored.loc[y == 1, "ast_influence"].mean()),
            "thresholds": asdict(t),
        }
        (logger.info if result["passed"] else logger.error)("Layer verification: %s", result)
        return result

    # ------------------------------------------------------------------ #
    # Reports
    # ------------------------------------------------------------------ #
    def build_reports(self, frame: pd.DataFrame, ast_results: list[dict[str, Any]], top_k: int = 5) -> list[dict[str, Any]]:
        """Structured JSON-serialisable risk reports, one per row of ``frame``."""
        scored = self.score_frame(frame)
        X = self.pipeline.transform(frame)
        names = self.pipeline.feature_names_
        imp = self.classifier.feature_importances_
        weight = imp / max(imp.sum(), 1e-12) + 1.0 / len(names)
        reports = []
        for i in range(len(frame)):
            row, s, res = frame.iloc[i], scored.iloc[i], ast_results[i]
            contrib = np.abs(X[i]) * weight
            top = np.argsort(contrib)[::-1][:top_k]
            verification = {
                "ast_schema_ok": True,  # transform() would have raised otherwise
                "ast_digest_verified": bool(row.get("feature_digest")),
                "ast_features_in_model_input": bool(s["ast_in_model_input"]),
                "ast_nonzero_features": int(s["ast_nonzero_features"]),
                "astmaster_available": bool(row.get("astmaster_available")),
                "models_responded": bool(np.isfinite([s["threat_probability"], s["anomaly_score"]]).all()),
            }
            verification["passed"] = all(v for k, v in verification.items() if k != "ast_nonzero_features") \
                and verification["ast_nonzero_features"] > 0
            reports.append({
                "package_name": str(row["package_name"]),
                "risk_score": round(float(s["risk_score"]), 4),
                "severity": str(s["severity"]),
                "action": str(s["action"]),
                "flagged": bool(s["flagged"]),
                "predicted_attack_type": str(s["predicted_attack_type"]),
                "closest_known_attack": str(s["closest_attack"]),
                "detection_layers": [x for x in str(s["detection_layers"]).split(",") if x],
                "layers": {
                    "ast_static": {"score": round(float(s["static_risk"]), 4), "verdict": str(row["static_verdict"]),
                                   "source": str(row["static_source"]),
                                   "component": round(float(s["static_component"]), 4)},
                    "supervised": {"threat_probability": round(float(s["threat_probability"]), 4),
                                   "closest_attack_confidence": round(float(s["closest_attack_confidence"]), 4),
                                   "escalated_critical_family": bool(s["escalated"]),
                                   "corroborated_by_ast": bool(s["corroborated"])},
                    "anomaly": {"percentile": round(float(s["anomaly_score"]), 4),
                                "component": round(float(s["anomaly_component"]), 4)},
                },
                "ast_influence": {
                    "risk_without_ast": round(float(s["risk_without_ast"]), 4),
                    "delta": round(float(s["ast_influence"]), 4),
                    "verdict_changes_without_ast": bool(s["flagged"]) != bool(s["flagged_without_ast"]),
                },
                "findings": res.get("findings", [])[:10],
                # Node-level evidence from the AST service (already sorted most-severe first).
                "ast_risky_nodes": res.get("risky_nodes", [])[:25],
                "top_factors": [{"feature": names[j], "value": round(float(row[names[j]]), 4),
                                 "z_score": round(float(X[i, j]), 3)} for j in top if contrib[j] > 0],
                "verification": verification,
            })
        return reports

    # ------------------------------------------------------------------ #
    # Persistence
    # ------------------------------------------------------------------ #
    def save(self, directory: str | Path, extra: dict[str, Any] | None = None) -> Path:
        """Write ``.joblib`` components and a SHA-256 manifest (HMAC-signed if ``SCS_HMAC_KEY`` is set)."""
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        objs = {"pipeline": self.pipeline, "detector": self.detector, "classifier": self.classifier}
        hashes = {}
        for key, fname in _COMPONENTS.items():
            joblib.dump(objs[key], directory / fname, compress=3)
            hashes[fname] = _sha256(directory / fname)
        manifest: dict[str, Any] = {
            "schema_version": 1, "package_version": __version__,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "library_versions": {"python": platform.python_version(), "scikit-learn": sklearn.__version__,
                                 "numpy": np.__version__, "pandas": pd.__version__},
            "hybrid_config": asdict(self.config), "files": hashes,
            "ast_features": self.pipeline.ast_features_,
            "metadata": {**self.metadata, **(extra or {})},
        }
        if key := os.environ.get(HMAC_ENV_VAR):
            manifest["signature"] = self._sign(manifest, key)
        path = directory / MANIFEST_NAME
        path.write_text(json.dumps(manifest, indent=2, default=str), encoding="utf-8")
        return path

    @classmethod
    def load(cls, directory: str | Path) -> HybridScorer:
        """Verify hashes (and signature, if keyed) *before* unpickling, then load."""
        directory = Path(directory)
        mpath = directory / MANIFEST_NAME
        if not mpath.exists():
            raise FileNotFoundError(f"no {MANIFEST_NAME} in {directory}; run training first")
        manifest = json.loads(mpath.read_text(encoding="utf-8"))
        if key := os.environ.get(HMAC_ENV_VAR):
            sig = manifest.get("signature")
            if not sig or not hmac.compare_digest(sig, cls._sign(manifest, key)):
                raise ArtifactIntegrityError("manifest signature missing or invalid")
        loaded = {}
        for comp, fname in _COMPONENTS.items():
            expected = manifest["files"].get(fname)
            if not expected or not hmac.compare_digest(_sha256(directory / fname), expected):
                raise ArtifactIntegrityError(f"hash mismatch for {fname}")
            loaded[comp] = joblib.load(directory / fname)
        scorer = cls(loaded["pipeline"], loaded["detector"], loaded["classifier"],
                     HybridConfig.from_dict(manifest["hybrid_config"]))
        scorer.metadata = {**manifest.get("metadata", {}), "created_at": manifest.get("created_at")}
        return scorer

    @staticmethod
    def _sign(manifest: dict[str, Any], key: str) -> str:
        body = json.dumps({k: v for k, v in manifest.items() if k != "signature"}, sort_keys=True, default=str)
        return hmac.new(key.encode(), body.encode(), hashlib.sha256).hexdigest()
