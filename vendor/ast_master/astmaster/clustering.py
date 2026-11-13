"""Phase 3: compare a file's structure with known attack patterns.

Files become vectors of AST-derived features, then MiniBatchKMeans groups them
with the reference vectors stored in SQLite. A file matches only if it lands in
an attack-heavy cluster, and is both close to a known attack and closer to it than
to any benign reference.

This phase can raise a file's rating but never lower it, so a weak model can't
hide what the rules found. scikit-learn is imported on first use, which keeps
the cost away from runs that don't reach this phase.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass

from .security import RULES, FileSignals, Finding, file_kind

FEATURE_VERSION = 3
_CAPS = ("exec", "shell", "network", "secret", "recon", "obfuscation", "persist")
_CONTEXTS = ("install", "import", "runtime")
_EXTRA_RULES = ("silent-sink", "install-hook", "native-code", "self-delete", "whitespace-hidden")
_STRUCTURE = ("functions", "nested_functions", "loops", "max_loop_depth", "threads", "module_calls")
_CLUSTERS = 16
_ATTACK_CLUSTER_SHARE = 0.34
_DISTANCE_QUANTILE = 0.9

FEATURE_NAMES = (
    *(f"{cap}:{context}" for cap in _CAPS for context in _CONTEXTS),
    *(f"rule:{rule}" for rule in _EXTRA_RULES),
    *(f"structure:{name}" for name in _STRUCTURE),
    "kind:install",
)


def build_vector(path: str, signals: FileSignals, findings: list[Finding]) -> list[float]:
    counts = dict.fromkeys(FEATURE_NAMES, 0.0)
    for finding in findings:
        context = finding.context if finding.context in _CONTEXTS else "install"
        for cap in RULES[finding.rule].caps:
            if cap in _CAPS:
                counts[f"{cap}:{context}"] += 1
        if finding.rule in _EXTRA_RULES:
            counts[f"rule:{finding.rule}"] += 1
    for name in _STRUCTURE:
        counts[f"structure:{name}"] = float(signals.structure.get(name, 0))
    counts["kind:install"] = float(file_kind(path) == "install")
    # Log scale, so one huge file can't dominate every distance.
    return [math.log1p(counts[name]) for name in FEATURE_NAMES]


def has_capabilities(vector: list[float]) -> bool:
    return any(vector[:len(_CAPS) * len(_CONTEXTS)])


@dataclass(slots=True)
class ClusterMatch:
    signature: str
    category: str
    distance: float
    cluster: int


class AttackClusterModel:
    def __init__(self, rows: list[dict]) -> None:
        import numpy as np
        from sklearn.cluster import MiniBatchKMeans

        self._np = np
        attacks = [r for r in rows if r["label"] == "attack"]
        benign = [r for r in rows if r["label"] == "benign"]
        if not attacks or not benign:
            raise ValueError("needs both attack and benign reference vectors")
        self._attack_rows = attacks
        self._attacks = np.array([r["vector"] for r in attacks], dtype=float)
        self._benign = np.array([r["vector"] for r in benign], dtype=float)
        features = np.vstack([self._attacks, self._benign])
        # Attack samples are rare, so weight them to shape the clusters anyway.
        weights = np.concatenate([
            np.full(len(attacks), max(1.0, len(benign) / len(attacks))), np.ones(len(benign)),
        ])
        self._model = MiniBatchKMeans(
            n_clusters=min(_CLUSTERS, len(features)), random_state=0, batch_size=128, n_init=3,
        ).fit(features, sample_weight=weights)
        labels = self._model.labels_
        attack_labels = labels[:len(attacks)]
        self._attack_share = {}
        for cluster in range(self._model.n_clusters):
            members = int((labels == cluster).sum())
            self._attack_share[cluster] = float((attack_labels == cluster).sum()) / members if members else 0.0
        self._radius = self._distance_limit()

    def _distance_limit(self) -> float:
        np = self._np
        if len(self._attacks) < 2:
            return 1.0
        pairwise = np.linalg.norm(self._attacks[:, None] - self._attacks[None, :], axis=2)
        np.fill_diagonal(pairwise, np.inf)
        return float(np.quantile(pairwise.min(axis=1), _DISTANCE_QUANTILE))

    def classify(self, vector: list[float]) -> ClusterMatch | None:
        if not has_capabilities(vector):
            return None
        np = self._np
        point = np.array(vector, dtype=float)
        cluster = int(self._model.predict(point.reshape(1, -1))[0])
        if self._attack_share[cluster] < _ATTACK_CLUSTER_SHARE:
            return None
        distances = np.linalg.norm(self._attacks - point, axis=1)
        nearest = int(distances.argmin())
        distance = float(distances[nearest])
        if distance > self._radius or distance >= float(np.linalg.norm(self._benign - point, axis=1).min()):
            return None
        row = self._attack_rows[nearest]
        return ClusterMatch(row["name"], row["category"], round(distance, 3), cluster)


class ClusterService:
    """Fits once, on first use, from the signatures in SQLite."""

    def __init__(self, load_rows) -> None:
        self._load_rows = load_rows
        self._lock = threading.Lock()
        self._model: AttackClusterModel | None = None
        self.unavailable: str | None = None

    def model(self) -> AttackClusterModel | None:
        with self._lock:
            if self._model is None and self.unavailable is None:
                try:
                    self._model = AttackClusterModel(self._load_rows())
                except ImportError:
                    self.unavailable = "scikit-learn isn't installed (use .venv/bin/python)"
                except ValueError as error:
                    self.unavailable = str(error)
            return self._model
