"""Random Forest wrapper for supervised classification of known supply chain attacks."""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.base import ClassifierMixin
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import average_precision_score
from sklearn.model_selection import RandomizedSearchCV, StratifiedKFold

from ai_engine.config import BENIGN_LABEL, RANDOM_STATE

logger = logging.getLogger(__name__)

DEFAULT_SEARCH_SPACE: dict[str, Sequence[Any]] = {
    "n_estimators": (200, 300, 400),
    "max_depth": (None, 12, 20, 30),
    "min_samples_leaf": (1, 2, 4),
    "max_features": ("sqrt", "log2", 0.3),
}


def threat_average_precision(estimator: ClassifierMixin, X: np.ndarray, y: np.ndarray) -> float:
    """Scorer: average precision of ``P(not benign)`` against binary malicious labels.

    Optimising this ranks threats above benign traffic regardless of the exact
    family, which is what the downstream hybrid scorer consumes.
    """
    classes = list(estimator.classes_)
    proba = estimator.predict_proba(X)
    p_threat = 1.0 - proba[:, classes.index(BENIGN_LABEL)] if BENIGN_LABEL in classes else proba.max(axis=1)
    return float(average_precision_score(np.asarray(y) != BENIGN_LABEL, p_threat))


class ThreatClassifier:
    """Multi-class Random Forest over ``benign`` + known attack families.

    Args:
        n_estimators: Number of trees.
        max_depth: Maximum tree depth (``None`` = unlimited).
        min_samples_leaf: Minimum samples per leaf.
        max_features: Features considered per split.
        class_weight: Class weighting; ``balanced_subsample`` counters the heavy
            benign/attack imbalance.
        random_state: Seed.
        n_jobs: Parallel jobs.
    """

    def __init__(
        self,
        n_estimators: int = 300,
        max_depth: int | None = None,
        min_samples_leaf: int = 1,
        max_features: str | float = "sqrt",
        class_weight: str | dict[str, float] | None = "balanced_subsample",
        random_state: int = RANDOM_STATE,
        n_jobs: int | None = -1,
    ) -> None:
        self.n_estimators = n_estimators
        self.max_depth = max_depth
        self.min_samples_leaf = min_samples_leaf
        self.max_features = max_features
        self.class_weight = class_weight
        self.random_state = random_state
        self.n_jobs = n_jobs
        self.model_: RandomForestClassifier | None = None
        self.best_params_: dict[str, Any] | None = None
        self.cv_score_: float | None = None

    def _build(self, **overrides: Any) -> RandomForestClassifier:
        params: dict[str, Any] = {
            "n_estimators": self.n_estimators,
            "max_depth": self.max_depth,
            "min_samples_leaf": self.min_samples_leaf,
            "max_features": self.max_features,
            "class_weight": self.class_weight,
            "random_state": self.random_state,
            "n_jobs": self.n_jobs,
        }
        params.update(overrides)
        return RandomForestClassifier(**params)

    def fit(self, X: np.ndarray, y: Sequence[str] | np.ndarray) -> ThreatClassifier:
        """Fit with the current hyperparameters."""
        y = np.asarray(y)
        if BENIGN_LABEL not in set(y):
            raise ValueError(f"Training labels must include the '{BENIGN_LABEL}' class")
        self.model_ = self._build().fit(X, y)
        return self

    def tune(
        self,
        X: np.ndarray,
        y: Sequence[str] | np.ndarray,
        n_iter: int = 10,
        cv: int = 3,
        search_space: Mapping[str, Sequence[Any]] | None = None,
    ) -> ThreatClassifier:
        """Randomised hyperparameter search with stratified CV, then refit on all data.

        Args:
            X: Training matrix.
            y: Attack-family labels (must include ``benign``).
            n_iter: Number of sampled configurations.
            cv: Number of stratified folds.
            search_space: Parameter distributions; defaults to :data:`DEFAULT_SEARCH_SPACE`.
        """
        y = np.asarray(y)
        search = RandomizedSearchCV(
            self._build(),
            param_distributions=dict(search_space or DEFAULT_SEARCH_SPACE),
            n_iter=n_iter,
            scoring=threat_average_precision,
            cv=StratifiedKFold(n_splits=cv, shuffle=True, random_state=self.random_state),
            random_state=self.random_state,
            n_jobs=1,  # the forest itself is parallel
            refit=True,
        )
        search.fit(X, y)
        self.best_params_ = dict(search.best_params_)
        self.cv_score_ = float(search.best_score_)
        for key, value in self.best_params_.items():
            setattr(self, key, value)
        self.model_ = search.best_estimator_
        logger.info("Best RandomForest params %s (CV threat AP %.4f)", self.best_params_, self.cv_score_)
        return self

    @property
    def classes_(self) -> np.ndarray:
        """Class labels in ``predict_proba`` column order."""
        return self._model.classes_

    @property
    def feature_importances_(self) -> np.ndarray:
        """Mean decrease in impurity per model-matrix column."""
        return self._model.feature_importances_

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Per-class probabilities, columns ordered as :attr:`classes_`."""
        return self._model.predict_proba(X)

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Most likely class label per row."""
        return self._model.predict(X)

    def threat_probability(self, X: np.ndarray) -> np.ndarray:
        """``1 - P(benign)`` per row."""
        proba = self.predict_proba(X)
        return 1.0 - proba[:, list(self.classes_).index(BENIGN_LABEL)]

    def closest_attack(self, X: np.ndarray, proba: np.ndarray | None = None) -> tuple[np.ndarray, np.ndarray]:
        """Most likely *non-benign* family and its probability per row."""
        proba = self.predict_proba(X) if proba is None else proba
        classes = np.asarray(self.classes_)
        attack_cols = np.flatnonzero(classes != BENIGN_LABEL)
        if attack_cols.size == 0:
            return np.full(len(proba), BENIGN_LABEL, dtype=object), np.zeros(len(proba))
        best = attack_cols[np.argmax(proba[:, attack_cols], axis=1)]
        return classes[best], proba[np.arange(len(proba)), best]

    def save(self, path: str | Path) -> None:
        """Serialise to ``path`` with joblib."""
        joblib.dump(self, Path(path))

    @staticmethod
    def load(path: str | Path) -> ThreatClassifier:
        """Load a classifier saved by :meth:`save` (only load trusted files)."""
        obj = joblib.load(Path(path))
        if not isinstance(obj, ThreatClassifier):
            raise TypeError(f"{path} does not contain a ThreatClassifier")
        return obj

    @property
    def _model(self) -> RandomForestClassifier:
        if self.model_ is None:
            raise RuntimeError("ThreatClassifier is not fitted")
        return self.model_
