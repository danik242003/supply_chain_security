"""Train the AI engine on AST-parsed packages and serialise ``.joblib`` artifacts.

Flow:
    1. Collect labelled packages: synthetic (generated) and/or real ones from ``--real-data DIR``
       (see :mod:`ai_engine.data.real_dataset`). Everything runs locally: no external AI or APIs.
    2. Send every package to the AST detection service; verify each response digest.
    3. Build the combined AST + metadata feature frame; stratified train/val/test split
       (real data is split per package, so a package's files never cross splits).
    4. Random Forest on known families (randomised search unless ``--quick``).
    5. Isolation Forest on benign training packages; percentile-calibrated on benign validation.
    6. Hybrid calibration on validation (floors, thresholds, static weight).
    7. Test-set evaluation (includes the never-seen novel family), plus a real-data-only view.
    8. Layer verification: training fails (exit 2) unless the AST layer and the
       ML layer are both shown to drive the verdicts.
    9. Save artifacts, manifest and ``training_report.json``.

Usage::

    python -m ai_engine.train [--quick] [--artifacts DIR] [--ast-url URL] [--real-data DIR [--no-synthetic]]
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from ai_engine.ast_client import ASTServiceClient
from ai_engine.config import ARTIFACT_DIR, BENIGN_LABEL, RANDOM_STATE
from ai_engine.data.generator import PackageGeneratorConfig, SyntheticPackageGenerator
from ai_engine.data.loader import PackageLoadError
from ai_engine.data.real_dataset import file_level_samples, load_labeled_dataset, split_by_package
from ai_engine.evaluate import evaluate_frame, format_report
from ai_engine.events import EventEmitter
from ai_engine.features.pipeline import FeaturePipeline, build_frame
from ai_engine.models.anomaly_detector import AnomalyDetector
from ai_engine.models.hybrid_scorer import HybridConfig, HybridScorer, VerificationThresholds
from ai_engine.models.threat_classifier import ThreatClassifier

logger = logging.getLogger("ai_engine.train")


class LayerVerificationError(RuntimeError):
    """Raised when training cannot prove both AST and ML layers contribute."""


class TrainingDataError(ValueError):
    """The selected data sources cannot produce valid train/validation splits."""


@dataclass
class TrainingConfig:
    """Training options."""

    artifact_dir: Path = ARTIFACT_DIR
    ast_url: str | None = None
    n_benign: int = 900
    seed: int = RANDOM_STATE
    tune: bool = True
    rf_search_iter: int = 10
    cv_folds: int = 3
    min_precision: float = 0.9
    file_level_rate: float = 0.5   # also train on single files (how scanner.py / uploads score them)
    enforce_verification: bool = True
    n_jobs: int = -1
    real_data_dir: Path | None = None   # labelled real packages (<dir>/<label>/<package>)
    synthetic: bool = True              # include generated packages


#: Raw source bytes per /analyze/batch request (the AST service caps the JSON body at 64 MB).
MAX_BATCH_SOURCE_BYTES = 24 * 1024 * 1024


def analyze_sized(client: ASTServiceClient, packages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """``analyze_batch`` in chunks bounded by count and source size (real packages can be large)."""
    results: list[dict[str, Any]] = []
    chunk: list[dict[str, Any]] = []
    size = 0
    for pkg in packages:
        pkg_size = sum(len(src) for src in pkg["files"].values())
        if chunk and (len(chunk) >= 100 or size + pkg_size > MAX_BATCH_SOURCE_BYTES):
            results.extend(client.analyze_batch(chunk, chunk_size=len(chunk)))
            chunk, size = [], 0
        chunk.append(pkg)
        size += pkg_size
    if chunk:
        results.extend(client.analyze_batch(chunk, chunk_size=len(chunk)))
    return results


def _collect_packages(cfg: TrainingConfig) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Synthetic + real packages; real ones carry their pre-assigned ``split``."""
    packages: list[dict[str, Any]] = []
    info: dict[str, Any] = {"synthetic_packages": 0, "real_packages": 0}
    if cfg.synthetic:
        generator = SyntheticPackageGenerator(PackageGeneratorConfig(n_benign=cfg.n_benign, seed=cfg.seed))
        synthetic = generator.generate()
        if cfg.file_level_rate > 0:
            singles = generator.file_level_samples(synthetic, benign_rate=cfg.file_level_rate)
            logger.info("Added %d synthetic single-file samples (file-level scoring)", len(singles))
            synthetic = synthetic + singles
        packages += [{**p, "source": "synthetic"} for p in synthetic]
        info["synthetic_packages"] = len(synthetic)
    if cfg.real_data_dir is not None:
        real, skipped = load_labeled_dataset(cfg.real_data_dir)
        info.update(real_data_dir=str(cfg.real_data_dir), real_skipped=skipped)
        if not real:
            logger.warning("No labelled packages under %s; continuing without real data", cfg.real_data_dir)
        else:
            splits = split_by_package(real, seed=cfg.seed)
            for name, part in splits.items():
                expanded = part + (file_level_samples(part, seed=cfg.seed, benign_rate=cfg.file_level_rate)
                                   if cfg.file_level_rate > 0 else [])
                packages += [{**p, "split": name} for p in expanded]
            info["real_packages"] = len(real)
            info["real_classes"] = {str(k): int(v) for k, v in
                                    pd.Series([p["attack_type"] for p in real]).value_counts().items()}
            info["real_split_packages"] = {k: len(v) for k, v in splits.items()}
            logger.info("Loaded %d real packages from %s: %s", len(real), cfg.real_data_dir, info["real_classes"])
    if not packages:
        raise TrainingDataError("no training data: enable synthetic data or provide labelled packages via --real-data")
    return packages, info


def _split_frame(frame: pd.DataFrame, seed: int) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Synthetic rows: stratified random split. Real rows: their package-level split."""
    syn = frame[frame["source"] == "synthetic"]
    real = frame[frame["source"] == "real"]
    parts: dict[str, list[pd.DataFrame]] = {"train": [], "val": [], "test": []}
    if len(syn):
        tr, rest = train_test_split(syn, test_size=0.4, stratify=syn["attack_type"], random_state=seed)
        va, te = train_test_split(rest, test_size=0.5, stratify=rest["attack_type"], random_state=seed)
        for name, part in (("train", tr), ("val", va), ("test", te)):
            parts[name].append(part)
    for name in parts:
        parts[name].append(real[real["split"] == name])
    train, val, test = (pd.concat(parts[n]) for n in ("train", "val", "test"))
    for name, part in (("train", train[train["is_novel"] == 0]), ("validation", val[val["is_novel"] == 0])):
        labels = set(part["is_malicious"].astype(int))
        if labels != {0, 1}:
            raise TrainingDataError(f"{name} split needs both benign and known-attack packages (has {sorted(labels)}); "
                             "add more labelled real data or keep synthetic data enabled")
    return train, val, test


def train_pipeline(cfg: TrainingConfig) -> dict[str, Any]:
    """Run the full workflow; returns the training report."""
    t0 = time.perf_counter()
    emitter = EventEmitter("trainer")
    client = ASTServiceClient(cfg.ast_url)
    health = client.wait_until_ready()
    emitter.emit("training.started", n_benign=cfg.n_benign, tune=cfg.tune, ast_backend=health["backend"])
    logger.info("AST service %s ready (astmaster available=%s)", client.base_url, health["backend"]["available"])

    packages, data_info = _collect_packages(cfg)
    logger.info("Analysing %d packages via AST service", len(packages))
    ast_results = analyze_sized(client, packages)
    frame = build_frame(packages, ast_results)
    frame["source"] = [p["source"] for p in packages]
    frame["split"] = [p.get("split") for p in packages]
    logger.info("Classes:\n%s", frame.groupby(["source", "attack_type"]).size().to_string())

    train, val, test = _split_frame(frame, cfg.seed)
    known_train = train[train["is_novel"] == 0]
    known_val = val[val["is_novel"] == 0]

    pipeline = FeaturePipeline().fit(known_train)
    X_train = pipeline.transform(known_train)
    y_train = known_train["attack_type"].to_numpy()
    X_val = pipeline.transform(known_val)
    y_val = known_val["is_malicious"].to_numpy(int)

    classifier = ThreatClassifier(random_state=cfg.seed, n_jobs=cfg.n_jobs)
    smallest = int(pd.Series(y_train).value_counts().min())
    if cfg.tune and smallest < cfg.cv_folds:
        logger.warning("Smallest training class has %d rows (< %d CV folds); skipping hyperparameter search",
                       smallest, cfg.cv_folds)
        classifier.fit(X_train, y_train)
    elif cfg.tune:
        classifier.tune(X_train, y_train, n_iter=cfg.rf_search_iter, cv=cfg.cv_folds)
    else:
        classifier.fit(X_train, y_train)

    X_benign = X_train[y_train == BENIGN_LABEL]
    if cfg.tune:
        detector = AnomalyDetector.tune(X_benign, X_val, y_val, random_state=cfg.seed, n_jobs=cfg.n_jobs)
    else:
        detector = AnomalyDetector(random_state=cfg.seed, n_jobs=cfg.n_jobs).fit(X_benign)
    detector.calibrate(X_val[y_val == 0])

    scorer = HybridScorer(pipeline, detector, classifier, HybridConfig(min_precision=cfg.min_precision))
    calibration = scorer.calibrate(known_val, y_val)

    test_metrics = evaluate_frame(scorer, test)
    logger.info("Test set (includes novel family):\n%s", format_report(test_metrics))
    real_test = test[test["source"] == "real"]
    real_test_metrics: dict[str, Any] | None = None
    if set(real_test["is_malicious"].astype(int)) == {0, 1}:
        real_test_metrics = evaluate_frame(scorer, real_test)
        logger.info("Real-data test set only:\n%s", format_report(real_test_metrics))
    elif len(real_test):
        logger.warning("Real-data test split lacks benign or malicious packages; no real-only metrics")

    verification = scorer.verify_layers(test, test["is_malicious"].to_numpy(int), VerificationThresholds())

    report = {
        "training_config": {k: str(v) if isinstance(v, Path) else v for k, v in asdict(cfg).items()},
        "ast_backend": health["backend"],
        "data_sources": data_info,
        "dataset": {"n_packages": len(frame), "classes": frame["attack_type"].value_counts().to_dict(),
                    "split": {"train": len(train), "val": len(val), "test": len(test)},
                    "n_ast_features": len(pipeline.ast_features_)},
        "random_forest": {"params": {k: getattr(classifier, k) for k in
                                     ("n_estimators", "max_depth", "min_samples_leaf", "max_features")},
                          "cv_threat_average_precision": classifier.cv_score_},
        "isolation_forest": {"params": detector.params},
        "hybrid_calibration": calibration,
        "test_metrics": test_metrics,
        "real_test_metrics": real_test_metrics,
        "layer_verification": verification,
        "top_features": sorted(({"feature": n, "importance": float(v)} for n, v in
                                zip(pipeline.feature_names_, classifier.feature_importances_)),
                               key=lambda d: -d["importance"])[:15],
        "training_seconds": round(time.perf_counter() - t0, 2),
    }
    cfg.artifact_dir.mkdir(parents=True, exist_ok=True)
    (cfg.artifact_dir / "training_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    emitter.emit("training.completed", passed=verification["passed"], verification=verification,
                 test_metrics={v: {k: test_metrics[v][k] for k in ("precision", "recall", "f1", "roc_auc",
                                                                  "false_positive_rate")}
                               for v in ("static_only", "supervised_only", "anomaly_only", "hybrid")},
                 per_family=test_metrics["per_family_detection_rate"], seconds=report["training_seconds"])
    emitter.flush()
    if cfg.enforce_verification and not verification["passed"]:
        failed = [k for k, ok in verification["checks"].items() if not ok]
        raise LayerVerificationError(f"layer verification failed: {failed}; artifacts NOT saved")
    scorer.save(cfg.artifact_dir, extra={
        "ast_backend": health["backend"], "test_hybrid_f1": test_metrics["hybrid"]["f1"],
        "layer_verification_passed": verification["passed"],
        "data_sources": {k: v for k, v in data_info.items() if k != "real_skipped"},
    })
    logger.info("Saved artifacts to %s in %.1fs", cfg.artifact_dir, report["training_seconds"])
    return report


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    ap = argparse.ArgumentParser(description="Train AST + ML supply chain detection models.")
    ap.add_argument("--artifacts", type=Path, default=ARTIFACT_DIR)
    ap.add_argument("--ast-url", help="AST service URL (default $AST_SERVICE_URL)")
    ap.add_argument("--n-benign", type=int, default=900)
    ap.add_argument("--seed", type=int, default=RANDOM_STATE)
    ap.add_argument("--quick", action="store_true", help="Skip hyperparameter search")
    ap.add_argument("--no-enforce-verification", action="store_true")
    ap.add_argument("--real-data", type=Path,
                    help="labelled real packages: DIR/<label>/<package> (label = benign or an attack family)")
    ap.add_argument("--no-synthetic", action="store_true", help="train on --real-data only")
    args = ap.parse_args(argv)
    if args.no_synthetic and args.real_data is None:
        ap.error("--no-synthetic requires --real-data")
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        train_pipeline(TrainingConfig(artifact_dir=args.artifacts, ast_url=args.ast_url, n_benign=args.n_benign,
                                      seed=args.seed, tune=not args.quick,
                                      enforce_verification=not args.no_enforce_verification,
                                      real_data_dir=args.real_data, synthetic=not args.no_synthetic))
    except (TrainingDataError, PackageLoadError) as exc:
        logger.error("%s", exc)
        return 1
    except LayerVerificationError as exc:
        logger.error("%s", exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
