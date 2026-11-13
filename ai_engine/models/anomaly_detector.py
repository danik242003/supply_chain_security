"""Isolation Forest wrapper for unsupervised supply chain anomaly detection."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import ParameterGrid

from ai_engine.config import RANDOM_STATE

logger = logging.getLogger(__name__)

DEFAULT_PARAM_GRID: dict[str, Sequence[Any]] = {
    "n_estimators": (150, 300),
    "max_samples": (256, 512, 0.5),
    "max_features": (0.5, 0.8, 1.0),
}


class AnomalyDetector:
    """Isolation Forest fitted on the benign baseline to surface novel behaviour.

    Two scores are exposed:

    * :meth:`raw_score` - the negated Isolation Forest ``score_samples``
      (higher = more anomalous); best for ranking metrics such as ROC-AUC.
    * :meth:`score` - a calibrated score in ``[0, 1)`` equal to the empirical
      percentile of the raw score among held-out benign reference events.
      ``0.99`` means "more anomalous than 99% of normal traffic", which makes
      thresholds interpretable as a false-positive budget.

    Args:
        n_estimators: Number of isolation trees.
        max_samples: Sub-sample size per tree (int count or float fraction).
        max_features: Fraction of features drawn per tree.
        random_state: Seed for reproducibility.
        n_jobs: Parallel jobs for fitting/scoring.
        feature_indices: Columns of the model matrix to use (``None`` = all).
            Restricting the forest to behavioural telemetry keeps static
            identity traits from diluting the anomaly signal.
    """

    def __init__(
        self,
        n_estimators: int = 300,
        max_samples: int | float | str = 256,
        max_features: float = 1.0,
        random_state: int = RANDOM_STATE,
        n_jobs: int | None = -1,
        feature_indices: Sequence[int] | None = None,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.max_features = max_features
        self.random_state = random_state
        self.n_jobs = n_jobs
        self.feature_indices = list(feature_indices) if feature_indices is not None else None
        self.model_: IsolationForest | None = None
        self.reference_scores_: np.ndarray | None = None
        self.tuning_results_: list[dict[str, Any]] = []

    @property
    def params(self) -> dict[str, Any]:
        """Current hyperparameters."""
        return {
            "n_estimators": self.n_estimators,
            "max_samples": self.max_samples,
            "max_features": self.max_features,
        }

    def fit(self, X: np.ndarray) -> AnomalyDetector:
        """Fit on (predominantly) benign events and self-calibrate on them.

        Call :meth:`calibrate` afterwards with held-out benign data for an
        unbiased percentile mapping.
        """
        max_samples = self.max_samples
        if isinstance(max_samples, int):
            max_samples = min(max_samples, len(X))
        self.model_ = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=max_samples,
            max_features=self.max_features,
            contamination="auto",
            random_state=self.random_state,
            n_jobs=self.n_jobs,
        ).fit(self._select(X))
        self.calibrate(X)
        return self

    def calibrate(self, X_reference: np.ndarray) -> AnomalyDetector:
        """Set the benign reference distribution used by :meth:`score`."""
        if len(X_reference) == 0:
            raise ValueError("Calibration requires at least one reference sample")
        self.reference_scores_ = np.sort(self.raw_score(X_reference))
        return self

    def raw_score(self, X: np.ndarray) -> np.ndarray:
        """Unbounded anomaly score; higher means more anomalous."""
        if self.model_ is None:
            raise RuntimeError("AnomalyDetector is not fitted")
        return -self.model_.score_samples(self._select(X))

    def _select(self, X: np.ndarray) -> np.ndarray:
        return X if self.feature_indices is None else X[:, self.feature_indices]

    def score(self, X: np.ndarray) -> np.ndarray:
        """Calibrated anomaly percentile in ``[0, 1)`` relative to benign reference data."""
        self._check_fitted()
        assert self.reference_scores_ is not None
        ranks = np.searchsorted(self.reference_scores_, self.raw_score(X), side="right")
        return ranks / (len(self.reference_scores_) + 1.0)

    @classmethod
    def tune(
        cls,
        X_fit: np.ndarray,
        X_val: np.ndarray,
        y_val: np.ndarray,
        param_grid: Mapping[str, Sequence[Any]] | None = None,
        random_state: int = RANDOM_STATE,
        n_jobs: int | None = -1,
        feature_indices: Sequence[int] | None = None,
    ) -> AnomalyDetector:
        """Grid-search hyperparameters by validation ROC-AUC.

        The forest is always fitted on ``X_fit`` (benign baseline); labels are
        used only to *select* hyperparameters, never to fit.

        Args:
            X_fit: Benign training matrix.
            X_val: Validation matrix containing benign and malicious rows.
            y_val: Binary validation labels (1 = malicious).
            param_grid: Grid over ``n_estimators``, ``max_samples``, ``max_features``.
            random_state: Seed.
            n_jobs: Parallel jobs per forest.
            feature_indices: Column subset passed to each candidate detector.

        Returns:
            The best fitted detector, with ``tuning_results_`` populated.
        """
        if len(np.unique(y_val)) < 2:
            raise ValueError("Validation labels must contain both classes for tuning")
        results: list[dict[str, Any]] = []
        best: AnomalyDetector | None = None
        best_auc = -np.inf
        for params in ParameterGrid(dict(param_grid or DEFAULT_PARAM_GRID)):
            detector = cls(random_state=random_state, n_jobs=n_jobs, feature_indices=feature_indices, **params).fit(X_fit)
            auc = float(roc_auc_score(y_val, detector.raw_score(X_val)))
            results.append({**params, "roc_auc": auc})
            logger.debug("IsolationForest %s -> val ROC-AUC %.4f", params, auc)
            if auc > best_auc:
                best, best_auc = detector, auc
        assert best is not None
        best.tuning_results_ = sorted(results, key=lambda r: r["roc_auc"], reverse=True)
        logger.info("Best IsolationForest params %s (val ROC-AUC %.4f)", best.params, best_auc)
        return best

    def save(self, path: str | Path) -> None:
        """Serialise to ``path`` with joblib."""
        joblib.dump(self, Path(path))

    @staticmethod
    def load(path: str | Path) -> AnomalyDetector:
        """Load a detector saved by :meth:`save` (only load trusted files)."""
        obj = joblib.load(Path(path))
        if not isinstance(obj, AnomalyDetector):
            raise TypeError(f"{path} does not contain an AnomalyDetector")
        return obj

    def _check_fitted(self) -> None:
        if self.model_ is None or self.reference_scores_ is None:
            raise RuntimeError("AnomalyDetector is not fitted")
