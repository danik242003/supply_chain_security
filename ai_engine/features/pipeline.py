"""Combine AST feature vectors (from the AST service) with registry metadata into model input.

Columns:
    * ``ast_*`` / ``am_*`` - static-analysis features exactly as received from the AST
      service (built-in extractor and AST Master respectively).
    * ``meta_*`` / ``name_*`` - registry metadata and package-name signals computed here.

The fitted :class:`FeaturePipeline` records which columns are AST features so the
hybrid engine can (a) verify they reached the model matrix and (b) ablate them to
measure how much the AST layer drives each prediction.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from functools import lru_cache
from typing import Any

import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

from ai_engine.config import BENIGN_LABEL, INTERNAL_NAMESPACE_PREFIXES, MAX_NAME_DISTANCE, POPULAR_PACKAGES
from ai_engine.data.loader import normalize_metadata

AST_PREFIXES: tuple[str, ...] = ("ast_", "am_")
METADATA_FEATURES: tuple[str, ...] = (
    "meta_log_package_age", "meta_log_maintainer_age", "meta_num_maintainers", "meta_maintainer_changed",
    "meta_version_major", "meta_version_jump", "meta_log_downloads", "meta_signed_commit_ratio",
    "meta_new_maintainer_account", "name_min_edit_distance", "name_is_popular", "name_typosquat_flag",
    "name_internal_pattern", "name_length", "name_digit_ratio",
)
_SEP = re.compile(r"[-_.]+")
_POPULAR_NORM = tuple((p, _SEP.sub("-", p)) for p in POPULAR_PACKAGES)


class FeatureSchemaError(ValueError):
    """Incoming features do not match what the models were trained on."""


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@lru_cache(maxsize=65536)
def nearest_popular(name: str) -> tuple[str | None, int]:
    """Closest popular package other than ``name`` itself, distance capped at MAX_NAME_DISTANCE."""
    raw = name.strip().lower()
    norm = _SEP.sub("-", raw)
    best, best_d = None, MAX_NAME_DISTANCE + 1
    for pop, pop_norm in _POPULAR_NORM:
        if pop == raw or abs(len(pop_norm) - len(norm)) >= best_d:
            continue
        d = levenshtein(norm, pop_norm)
        if d < best_d:
            best, best_d = pop, d
    return best, min(best_d, MAX_NAME_DISTANCE)


def metadata_features(name: str, metadata: dict[str, Any] | None) -> dict[str, float]:
    """Registry metadata + package-name features for one package."""
    m = normalize_metadata(metadata)
    lowered = name.lower()
    _, dist = nearest_popular(name)
    popular = lowered in POPULAR_PACKAGES
    return {
        "meta_log_package_age": math.log1p(max(m["package_age_days"], 0.0)),
        "meta_log_maintainer_age": math.log1p(max(m["maintainer_account_age_days"], 0.0)),
        "meta_num_maintainers": m["num_maintainers"],
        "meta_maintainer_changed": m["maintainer_changed"],
        "meta_version_major": m["version_major"],
        "meta_version_jump": m["version_jump"],
        "meta_log_downloads": math.log1p(max(m["downloads_weekly"], 0.0)),
        "meta_signed_commit_ratio": m["signed_commit_ratio"],
        "meta_new_maintainer_account": float(m["maintainer_account_age_days"] < 30),
        "name_min_edit_distance": float(dist),
        "name_is_popular": float(popular),
        "name_typosquat_flag": float(not popular and dist <= 2 and len(name) >= 4),
        "name_internal_pattern": float(lowered.startswith(INTERNAL_NAMESPACE_PREFIXES)),
        "name_length": float(len(name)),
        "name_digit_ratio": sum(c.isdigit() for c in name) / max(len(name), 1),
    }


def build_frame(packages: Sequence[dict[str, Any]], ast_results: Sequence[dict[str, Any]]) -> pd.DataFrame:
    """Join packages with their (verified) AST service results into one row per package.

    Label columns (``attack_type``, ``is_malicious``, ``is_novel``) are carried over when present.
    """
    if len(packages) != len(ast_results):
        raise ValueError("packages and ast_results must align")
    rows: list[dict[str, Any]] = []
    for i, (pkg, res) in enumerate(zip(packages, ast_results)):
        static = res["static_risk"]
        row: dict[str, Any] = {
            "package_id": pkg.get("package_id", f"pkg-{i:06d}"),
            "package_name": pkg["name"],
            "static_risk": float(static["score"]),
            "static_verdict": static.get("verdict") or "SAFE",
            "static_source": static.get("source", "unknown"),
            "astmaster_available": bool(res.get("backend", {}).get("available")),
            "feature_digest": res.get("feature_digest"),
            "n_findings": len(res.get("findings", [])),
        }
        row.update({k: float(v) for k, v in res["features"].items()})
        row.update(metadata_features(pkg["name"], pkg.get("metadata")))
        for label in ("attack_type", "is_malicious", "is_novel"):
            if label in pkg:
                row[label] = pkg[label]
        rows.append(row)
    return pd.DataFrame(rows)


class FeaturePipeline:
    """Standardises the combined AST + metadata feature table.

    Attributes (after :meth:`fit`):
        ast_features_: AST column names (``ast_*`` / ``am_*``) in model order.
        feature_names_: All model columns (AST first, then metadata).
        ast_reference_: Benign-median value of each AST feature, used for ablation.
    """

    def __init__(self) -> None:
        self.scaler_: StandardScaler | None = None
        self.ast_features_: list[str] = []
        self.feature_names_: list[str] = []
        self.ast_reference_: dict[str, float] = {}

    def fit(self, frame: pd.DataFrame) -> FeaturePipeline:
        """Learn the column set, scaling and benign AST reference from training rows."""
        self.ast_features_ = sorted(c for c in frame.columns if c.startswith(AST_PREFIXES))
        if not self.ast_features_:
            raise FeatureSchemaError("training frame contains no AST features")
        self.feature_names_ = self.ast_features_ + list(METADATA_FEATURES)
        self.scaler_ = StandardScaler().fit(frame[self.feature_names_].to_numpy(float))
        benign = frame[frame["attack_type"] == BENIGN_LABEL] if "attack_type" in frame else frame
        self.ast_reference_ = benign[self.ast_features_].median().astype(float).to_dict()
        return self

    def check_schema(self, frame: pd.DataFrame) -> None:
        """Raise :class:`FeatureSchemaError` if any trained feature is missing."""
        missing = [c for c in self.feature_names_ if c not in frame.columns]
        if missing:
            raise FeatureSchemaError(f"missing {len(missing)} feature(s), e.g. {missing[:5]}")

    def transform(self, frame: pd.DataFrame) -> np.ndarray:
        """Scaled model matrix (AST columns first)."""
        if self.scaler_ is None:
            raise RuntimeError("FeaturePipeline is not fitted")
        self.check_schema(frame)
        return self.scaler_.transform(frame[self.feature_names_].to_numpy(float))

    @property
    def ast_indices(self) -> list[int]:
        """Model-matrix positions of the AST features."""
        return list(range(len(self.ast_features_)))

    def ablate_ast(self, frame: pd.DataFrame) -> pd.DataFrame:
        """Copy of ``frame`` with every AST feature replaced by its benign reference value."""
        out = frame.copy()
        for col, value in self.ast_reference_.items():
            out[col] = value
        return out

    def ast_columns_reached_model(self, frame: pd.DataFrame, X: np.ndarray) -> np.ndarray:
        """Per-row check that the AST block of ``X`` equals the scaled service features."""
        assert self.scaler_ is not None
        n = len(self.ast_features_)
        expected = (frame[self.ast_features_].to_numpy(float) - self.scaler_.mean_[:n]) / self.scaler_.scale_[:n]
        return np.isclose(X[:, :n], expected, atol=1e-9).all(axis=1)
