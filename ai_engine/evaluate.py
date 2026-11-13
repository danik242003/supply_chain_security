"""Evaluation: Precision, Recall, F1, ROC-AUC, PR-AUC and confusion matrices.

Four views are compared on labelled data: AST static analysis alone, Random Forest
alone, Isolation Forest alone, and the hybrid engine, plus per-family detection
rates (including the novel family the classifier never saw).

Usage::

    python -m ai_engine.evaluate                 # fresh synthetic holdout via the AST service
    python -m ai_engine.evaluate --output metrics.json
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score

from ai_engine.ast_client import ASTServiceClient
from ai_engine.config import ARTIFACT_DIR, BENIGN_LABEL
from ai_engine.data.generator import PackageGeneratorConfig, SyntheticPackageGenerator
from ai_engine.features.pipeline import build_frame
from ai_engine.models.hybrid_scorer import HybridScorer

logger = logging.getLogger("ai_engine.evaluate")
VIEWS = ("static_only", "supervised_only", "anomaly_only", "hybrid")


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray | None = None) -> dict[str, Any]:
    """Binary detection metrics with malicious as the positive class."""
    y_true = np.asarray(y_true).astype(int)
    y_pred = np.asarray(y_pred).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    both = len(np.unique(y_true)) == 2 and y_score is not None
    return {
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_score)) if both else None,
        "pr_auc": float(average_precision_score(y_true, y_score)) if both else None,
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def evaluate_frame(scorer: HybridScorer, frame: pd.DataFrame) -> dict[str, Any]:
    """Evaluate all views on a labelled feature frame."""
    y = frame["is_malicious"].to_numpy(int)
    scored = scorer.score_frame(frame)
    cfg = scorer.config
    preds = {
        "static_only": ((frame["static_verdict"] != "SAFE").to_numpy(), frame["static_risk"].to_numpy(float)),
        "supervised_only": ((scored["threat_probability"] >= 0.5).to_numpy(), scored["threat_probability"].to_numpy()),
        "anomaly_only": ((scored["anomaly_score"] >= cfg.anomaly_floor).to_numpy(), scored["anomaly_raw"].to_numpy()),
        "hybrid": (scored["flagged"].to_numpy(), scored["risk_score"].to_numpy()),
    }
    results: dict[str, Any] = {"n_packages": int(len(frame))}
    for view, (pred, score) in preds.items():
        results[view] = compute_binary_metrics(y, pred, score)
    families: dict[str, dict[str, Any]] = {}
    for fam, idx in frame.groupby("attack_type").groups.items():
        mask = frame.index.isin(idx)
        families[str(fam)] = {"count": int(mask.sum()),
                              **{v: float(np.asarray(preds[v][0])[mask].mean()) for v in VIEWS}}
    results["per_family_detection_rate"] = families
    results["severity_distribution"] = scored["severity"].value_counts().to_dict()
    results["operating_point"] = {k: getattr(cfg, k) for k in
                                  ("decision_threshold", "critical_threshold", "static_weight", "static_floor", "anomaly_floor")}
    return results


def format_report(results: dict[str, Any]) -> str:
    """Plain-text rendering of :func:`evaluate_frame` output."""
    head = f"{'view':<17}{'prec':>7}{'recall':>8}{'f1':>7}{'roc_auc':>9}{'pr_auc':>8}{'fpr':>7}   tn/fp/fn/tp"
    lines = [f"Packages evaluated: {results['n_packages']}", "", head, "-" * len(head)]
    for v in VIEWS:
        m = results[v]
        cm = m["confusion_matrix"]
        auc = lambda x: f"{x:.3f}" if x is not None else "n/a"  # noqa: E731
        lines.append(f"{v:<17}{m['precision']:>7.3f}{m['recall']:>8.3f}{m['f1']:>7.3f}{auc(m['roc_auc']):>9}"
                     f"{auc(m['pr_auc']):>8}{m['false_positive_rate']:>7.3f}   {cm['tn']}/{cm['fp']}/{cm['fn']}/{cm['tp']}")
    lines += ["", "Detection rate per family (benign row = false-positive rate):",
              f"  {'family':<24}{'n':>5}" + "".join(f"{v.split('_')[0]:>12}" for v in VIEWS)]
    fams = results["per_family_detection_rate"]
    for fam in sorted(fams, key=lambda k: (k == BENIGN_LABEL, k)):
        r = fams[fam]
        lines.append(f"  {fam:<24}{r['count']:>5}" + "".join(f"{r[v]:>12.3f}" for v in VIEWS))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="Evaluate trained models on a fresh synthetic holdout.")
    ap.add_argument("--artifacts", type=Path, default=ARTIFACT_DIR)
    ap.add_argument("--ast-url", help="AST service URL (default $AST_SERVICE_URL)")
    ap.add_argument("--n-benign", type=int, default=600)
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--output", type=Path)
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    scorer = HybridScorer.load(args.artifacts)
    client = ASTServiceClient(args.ast_url)
    client.wait_until_ready()
    packages = SyntheticPackageGenerator(PackageGeneratorConfig(n_benign=args.n_benign, seed=args.seed)).generate()
    frame = build_frame(packages, client.analyze_batch(packages))
    results = evaluate_frame(scorer, frame)
    print(format_report(results))
    if args.output:
        args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
