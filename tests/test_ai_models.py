"""Unit tests for the ML layer: classifier, anomaly detector, fusion, feature pipeline, inference quality."""

from __future__ import annotations

import shutil
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from ai_engine.features.pipeline import FeaturePipeline, FeatureSchemaError, build_frame, metadata_features
from ai_engine.models.anomaly_detector import AnomalyDetector
from ai_engine.models.hybrid_scorer import ArtifactIntegrityError, HybridConfig, HybridScorer
from ai_engine.models.threat_classifier import ThreatClassifier

RNG = np.random.default_rng(0)


def _toy(n: int = 300) -> tuple[np.ndarray, np.ndarray]:
    benign = RNG.normal(0, 1, (n, 4))
    attack = RNG.normal(4, 1, (n // 5, 4))
    X = np.vstack([benign, attack])
    y = np.array(["benign"] * n + ["malicious_build_hook"] * (n // 5))
    return X, y


# --------------------------------------------------------------------------- #
# ThreatClassifier (Random Forest)
# --------------------------------------------------------------------------- #
def test_classifier_separates_and_reports_threat_probability() -> None:
    X, y = _toy()
    clf = ThreatClassifier(n_estimators=50, random_state=0).fit(X, y)
    p = clf.threat_probability(np.array([[0, 0, 0, 0], [4, 4, 4, 4]], dtype=float))
    assert p[0] < 0.2 < 0.8 < p[1]
    closest, conf = clf.closest_attack(np.array([[4.0, 4, 4, 4]]))
    assert closest[0] == "malicious_build_hook" and conf[0] > 0.8


def test_classifier_requires_benign_class() -> None:
    with pytest.raises(ValueError):
        ThreatClassifier().fit(np.zeros((4, 2)), ["a", "b", "a", "b"])


def test_unfitted_classifier_raises() -> None:
    with pytest.raises(RuntimeError):
        ThreatClassifier().predict_proba(np.zeros((1, 2)))


# --------------------------------------------------------------------------- #
# AnomalyDetector (Isolation Forest)
# --------------------------------------------------------------------------- #
def test_anomaly_detector_ranks_outliers_higher_and_calibrates() -> None:
    X = RNG.normal(0, 1, (500, 5))
    det = AnomalyDetector(n_estimators=100, random_state=0).fit(X)
    det.calibrate(RNG.normal(0, 1, (500, 5)))
    scores = det.score(np.vstack([np.zeros(5), np.full(5, 8.0)]))
    assert scores[1] > 0.99 > 0.6 > scores[0]
    held_out = det.score(RNG.normal(0, 1, (2000, 5)))
    assert 0.4 < held_out.mean() < 0.6  # percentiles of benign data are ~uniform


def test_anomaly_detector_feature_subset() -> None:
    X = RNG.normal(0, 1, (300, 6))
    det = AnomalyDetector(n_estimators=50, feature_indices=[0, 1], random_state=0).fit(X)
    moved = X[:5].copy()
    moved[:, 2:] += 100  # columns the detector ignores
    assert np.allclose(det.raw_score(X[:5]), det.raw_score(moved))


# --------------------------------------------------------------------------- #
# HybridScorer fusion policy
# --------------------------------------------------------------------------- #
CFG = HybridConfig(anomaly_floor=0.9, static_floor=0.3, static_weight=0.5, decision_threshold=0.5,
                   critical_threshold=0.3)


def _fuse(p, a, s, closest="typosquatting", **kw):
    out = HybridScorer.fuse(np.array([p]), np.array([a]), np.array([s]), np.array([closest]), CFG, **kw)
    return {k: v[0] for k, v in out.items()}


def test_fusion_gates_below_floor() -> None:
    assert _fuse(0.0, 0.85, 0.2)["risk_score"] == 0.0  # anomaly & static below their floors


def test_fusion_is_monotonic_in_every_layer() -> None:
    base = _fuse(0.2, 0.92, 0.4)["risk_score"]
    assert _fuse(0.4, 0.92, 0.4)["risk_score"] > base
    assert _fuse(0.2, 0.99, 0.4)["risk_score"] > base
    assert _fuse(0.2, 0.92, 0.9)["risk_score"] > base


def test_static_layer_alone_can_flag_and_is_weighted() -> None:
    r = _fuse(0.0, 0.0, 1.0)
    assert r["static_component"] == pytest.approx(0.5) and r["flagged"]
    assert _fuse(0.0, 0.0, 1.0, static_weight=0.25)["risk_score"] == pytest.approx(0.25)


def test_critical_family_escalation() -> None:
    assert not _fuse(0.35, 0, 0, closest="typosquatting")["flagged"]
    esc = _fuse(0.35, 0, 0, closest="malicious_build_hook")
    assert esc["flagged"] and esc["escalated"]


# --------------------------------------------------------------------------- #
# Feature pipeline
# --------------------------------------------------------------------------- #
def test_metadata_name_features() -> None:
    squat = metadata_features("reqeusts", {})
    assert squat["name_typosquat_flag"] == 1 and squat["name_min_edit_distance"] == 2
    real = metadata_features("requests", {})
    assert real["name_is_popular"] == 1 and real["name_typosquat_flag"] == 0
    assert metadata_features("acme-auth", {})["name_internal_pattern"] == 1


def test_pipeline_ast_columns_ablation_and_schema() -> None:
    frame = pd.DataFrame({
        "ast_exec_calls": [0.0, 0.0, 3.0], "am_risk_score": [0.0, 10.0, 90.0],
        **{c: [1.0, 1.0, 1.0] for c in metadata_features("x", {})},
        "attack_type": ["benign", "benign", "backdoored_dependency"],
    })
    pipe = FeaturePipeline().fit(frame)
    assert pipe.ast_features_ == ["am_risk_score", "ast_exec_calls"]
    X = pipe.transform(frame)
    assert pipe.ast_columns_reached_model(frame, X).all()
    ablated = pipe.ablate_ast(frame)
    assert ablated["ast_exec_calls"].tolist() == [0.0] * 3 and ablated["am_risk_score"].tolist() == [5.0] * 3
    with pytest.raises(FeatureSchemaError):
        pipe.transform(frame.drop(columns=["ast_exec_calls"]))
    with pytest.raises(FeatureSchemaError):
        FeaturePipeline().fit(frame.drop(columns=["ast_exec_calls", "am_risk_score"]))


# --------------------------------------------------------------------------- #
# Inference on models trained from AST-service features
# --------------------------------------------------------------------------- #
def test_inference_accuracy_on_unseen_holdout(trained_dir: Path, client) -> None:
    from ai_engine.data.generator import PackageGeneratorConfig, SyntheticPackageGenerator
    from ai_engine.evaluate import evaluate_frame

    scorer = HybridScorer.load(trained_dir)
    pkgs = SyntheticPackageGenerator(PackageGeneratorConfig(n_benign=250, seed=777)).generate()
    results = evaluate_frame(scorer, build_frame(pkgs, client.analyze_batch(pkgs)))
    hybrid = results["hybrid"]
    assert hybrid["roc_auc"] > 0.97 and hybrid["recall"] > 0.9 and hybrid["false_positive_rate"] < 0.03
    assert hybrid["false_positive_rate"] <= results["static_only"]["false_positive_rate"]
    assert results["per_family_detection_rate"]["credential_stealer"]["hybrid"] > 0.7  # novel family


def test_training_report_layer_verification(trained_dir: Path) -> None:
    import json

    v = json.loads((trained_dir / "training_report.json").read_text())["layer_verification"]
    assert v["passed"], v["checks"]
    assert v["rf_ast_importance_share"] >= 0.25
    assert v["hybrid_roc_auc"] > v["hybrid_roc_auc_without_ast"]


def test_artifact_roundtrip_and_tamper_detection(trained_dir: Path, tmp_path: Path) -> None:
    scorer = HybridScorer.load(trained_dir)
    assert scorer.config.decision_threshold > 0
    copy = tmp_path / "copy"
    shutil.copytree(trained_dir, copy)
    with (copy / "anomaly_detector.joblib").open("ab") as fh:
        fh.write(b"x")
    with pytest.raises(ArtifactIntegrityError):
        HybridScorer.load(copy)


def test_escalation_blocks_only_when_ast_corroborates(trained_dir: Path, client) -> None:
    """Metadata-driven escalation => review; escalation + AST MALICIOUS => block."""
    scorer = HybridScorer.load(trained_dir)
    pkgs = [{"name": "corrob", "files": {"m.py": "x = 1\n"}, "metadata": {}}]
    frame = build_frame(pkgs, client.analyze_batch(pkgs))
    # Force an escalation-only decision regardless of what this small model predicts.
    scorer.config.decision_threshold, scorer.config.critical_threshold = 0.999, 0.0
    scorer.config.critical_attack_types = tuple(c for c in scorer.classifier.classes_ if c != "benign")
    for verdict, expected in (("SAFE", "MEDIUM"), ("MALICIOUS", "CRITICAL")):
        frame["static_verdict"] = verdict
        row = scorer.score_frame(frame).iloc[0]
        assert row["escalated"] and row["severity"] == expected, (verdict, row["severity"])


def test_ast_corroboration_flags_any_family() -> None:
    """AST MALICIOUS + classifier >= critical threshold is a detection even for non-critical families."""
    p, a, s = np.array([0.35]), np.array([0.0]), np.array([0.0])
    alone = HybridScorer.fuse(p, a, s, np.array(["typosquatting"]), CFG)
    assert not alone["flagged"][0]
    both = HybridScorer.fuse(p, a, s, np.array(["typosquatting"]), CFG, static_malicious=np.array([True]))
    assert both["flagged"][0] and both["corroborated"][0]
    weak = HybridScorer.fuse(np.array([0.1]), a, s, np.array(["typosquatting"]), CFG, static_malicious=np.array([True]))
    assert not weak["corroborated"][0]  # the ML layer must agree too
