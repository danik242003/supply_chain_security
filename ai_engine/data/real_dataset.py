"""Labelled real-world packages for training. Fully offline: nothing is executed, imported or extracted.

Layout (the directory name is the label)::

    <root>/
      benign/                     clean packages
      typosquatting/              any attack family name: [a-z][a-z0-9_]*
      malicious_build_hook/
      ...
        <package>/                a package directory (optional package_meta.json)
        <file>.py                 a single source file
        <archive>.zip|.whl|.tar.gz|...   read in memory with scanner.iter_archive (zip-slip/bomb safe)
        <bundle>.json             {"packages": [{"name", "files", "metadata"?, "payload_files"?}, ...]}

``package_meta.json`` holds the registry metadata (see ``config.METADATA_DEFAULTS``) and,
optionally, ``"payload_files": ["pkg/evil.py", ...]``: the files that carry the malicious code.
Those become single-file training samples, which is how ``scanner.py`` and the dashboard
score files. Families listed in ``config.NOVEL_ATTACK_TYPES`` are never used for training;
they go to the test split only, to measure zero-day coverage.

Real samples are split by package (:func:`split_by_package`), so files of one package never
land in two different splits.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any

import numpy as np

from ai_engine.config import BENIGN_LABEL, NOVEL_ATTACK_TYPES
from ai_engine.data.loader import (
    METADATA_FILE,
    SKIP_DIRS,
    PackageLoadError,
    _wanted,
    load_bundle,
    load_package_dir,
    normalize_metadata,
)

logger = logging.getLogger(__name__)

LABEL_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
ARCHIVE_SUFFIXES = (".zip", ".whl", ".egg", ".tar.gz", ".tgz", ".tar", ".tar.bz2", ".tar.xz")
SOURCE_SUFFIXES = (".py", ".pyw", ".pth")
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
#: Must stay within the AST service limits (MAX_FILES_PER_PACKAGE, request body size).
MAX_FILES_PER_PACKAGE = 500
MAX_PACKAGE_BYTES = 24 * 1024 * 1024
_PRIORITY_NAMES = ("setup.py", "setup.cfg", "pyproject.toml", "__init__.py")


def _cap_files(files: dict[str, str], payload: list[str], origin: str) -> dict[str, str]:
    """Trim oversized packages, keeping payload files, install files and shallow modules first."""
    total = sum(len(s) for s in files.values())
    if len(files) <= MAX_FILES_PER_PACKAGE and total <= MAX_PACKAGE_BYTES:
        return files

    def rank(path: str) -> tuple[int, int, int, str]:
        p = PurePosixPath(path)
        return (path not in payload, p.name not in _PRIORITY_NAMES and not p.name.endswith(".pth"),
                len(p.parts), path)

    kept: dict[str, str] = {}
    budget = MAX_PACKAGE_BYTES
    for path in sorted(files, key=rank):
        if len(kept) >= MAX_FILES_PER_PACKAGE:
            break
        if len(files[path]) <= budget:
            kept[path] = files[path]
            budget -= len(files[path])
    logger.warning("%s: %d files / %.1f MB exceeds AST limits; kept %d files", origin, len(files),
                   total / 1e6, len(kept))
    return kept


def _payload_list(value: Any) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def _from_archive(path: Path) -> dict[str, str]:
    """Analysable members of an archive, read in memory (never extracted)."""
    from scanner import iter_archive  # project-root module; shares the scanner's archive safety limits

    if path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise PackageLoadError(f"archive larger than {MAX_ARCHIVE_BYTES // 2**20} MB")
    files: dict[str, str] = {}
    for item in iter_archive(path.read_bytes(), path.name):
        inner = PurePosixPath(item.inner_path)
        if item.data is None or any(part in SKIP_DIRS for part in inner.parts) or not _wanted(Path(inner.name)):
            continue
        files[str(inner)] = item.data.decode("utf-8", errors="replace")
    if not files:
        raise PackageLoadError("no analysable files in archive (encrypted archives must be decrypted first)")
    return files


def _load_entry(path: Path) -> list[dict[str, Any]]:
    """One label-directory entry -> raw ``{"name", "files", "metadata", "payload_files"}`` records."""
    lower = path.name.lower()
    if path.is_dir():
        pkg = load_package_dir(path)
        raw_meta: dict[str, Any] = {}
        if (path / METADATA_FILE).is_file():
            raw_meta = json.loads((path / METADATA_FILE).read_text(encoding="utf-8"))
        return [{**pkg, "payload_files": _payload_list(raw_meta.get("payload_files"))}]
    if lower.endswith(".json"):
        raw = json.loads(path.read_text(encoding="utf-8"))
        raw_list = raw.get("packages") if isinstance(raw, dict) else raw
        return [{**pkg, "payload_files": _payload_list(r.get("payload_files"))}
                for pkg, r in zip(load_bundle(path), raw_list)]
    if lower.endswith(ARCHIVE_SUFFIXES):
        name = re.sub(r"(\.tar)?\.[a-z0-9]+$", "", path.name, flags=re.I)
        return [{"name": name, "files": _from_archive(path), "metadata": normalize_metadata(None),
                 "payload_files": []}]
    if lower.endswith(SOURCE_SUFFIXES):
        return [{**load_package_dir(path), "payload_files": []}]
    raise PackageLoadError("unsupported entry (expected a directory, .py, .json bundle or archive)")


def _digest(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for path in sorted(files):
        h.update(path.encode() + b"\0" + files[path].encode("utf-8", "replace") + b"\0")
    return h.hexdigest()


def load_labeled_dataset(root: str | Path, novel_families: tuple[str, ...] = NOVEL_ATTACK_TYPES,
                         ) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Load every labelled package under ``root``.

    Returns:
        ``(samples, skipped)``. Samples use the synthetic generator's format plus
        ``source="real"``, ``group_id`` and ``origin``; ``skipped`` lists ``{"path", "reason"}``.
    """
    root = Path(root)
    if not root.is_dir():
        raise PackageLoadError(f"real data directory {root} does not exist")
    samples: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    seen: dict[str, tuple[str, str]] = {}
    for label_dir in sorted(p for p in root.iterdir() if p.is_dir() and not p.is_symlink()):
        label = label_dir.name
        if label.startswith("."):
            continue
        if not LABEL_RE.match(label):
            skipped.append({"path": str(label_dir), "reason": "label folder must match [a-z][a-z0-9_]*"})
            continue
        for entry in sorted(label_dir.iterdir()):
            origin = str(entry.relative_to(root))
            if entry.is_symlink() or entry.name.startswith(".") or entry.name.lower() == "readme.md":
                continue
            try:
                records = _load_entry(entry)
            except (PackageLoadError, OSError, ValueError, json.JSONDecodeError) as exc:
                skipped.append({"path": origin, "reason": str(exc)})
                continue
            for i, rec in enumerate(records):
                rec_origin = origin if len(records) == 1 else f"{origin}#{i}"
                payload = [p for p in rec["payload_files"] if p in rec["files"]]
                files = _cap_files(rec["files"], payload, rec_origin)
                digest = _digest(files)
                if digest in seen:
                    prev_origin, prev_label = seen[digest]
                    why = "label conflict with" if prev_label != label else "duplicate of"
                    skipped.append({"path": rec_origin, "reason": f"{why} {prev_origin}"})
                    continue
                seen[digest] = (rec_origin, label)
                pid = f"real-{len(samples) + 1:06d}"
                samples.append({
                    "package_id": pid, "group_id": pid, "name": rec["name"], "files": files,
                    "metadata": rec["metadata"], "attack_type": label,
                    "is_malicious": int(label != BENIGN_LABEL), "is_novel": int(label in novel_families),
                    "payload_files": payload, "source": "real", "origin": rec_origin,
                })
    for item in skipped:
        logger.warning("real data: skipped %s (%s)", item["path"], item["reason"])
    return samples, skipped


def split_by_package(samples: list[dict[str, Any]], seed: int, val_frac: float = 0.2, test_frac: float = 0.2,
                     ) -> dict[str, list[dict[str, Any]]]:
    """Stratified (per label) package-level split into ``train`` / ``val`` / ``test``.

    Novel families go entirely to ``test``. A known family with fewer than 3 packages goes
    entirely to ``train`` (it cannot be validated or tested) and a warning is logged.
    """
    rng = np.random.default_rng(seed)
    by_label: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for s in samples:
        by_label[s["attack_type"]].append(s)
    out: dict[str, list[dict[str, Any]]] = {"train": [], "val": [], "test": []}
    for label in sorted(by_label):
        group = [by_label[label][i] for i in rng.permutation(len(by_label[label]))]
        if group[0]["is_novel"]:
            out["test"].extend(group)
            continue
        n = len(group)
        if n < 3:
            logger.warning("real data: only %d '%s' package(s); all used for training, none held out", n, label)
            out["train"].extend(group)
            continue
        n_val = max(1, round(n * val_frac))
        n_test = max(1, round(n * test_frac))
        out["val"].extend(group[:n_val])
        out["test"].extend(group[n_val:n_val + n_test])
        out["train"].extend(group[n_val + n_test:])
    return out


def file_level_samples(samples: list[dict[str, Any]], seed: int, benign_rate: float = 0.5,
                       ) -> list[dict[str, Any]]:
    """Single-file samples (same rules as the synthetic generator), keeping ``group_id``.

    Benign packages: a ``benign_rate`` fraction is split into one sample per file.
    Malicious packages: only their declared ``payload_files``, each with the package label.
    """
    rng = np.random.default_rng(seed)
    out: list[dict[str, Any]] = []
    for s in samples:
        if s["is_malicious"]:
            paths = s["payload_files"] if len(s["files"]) > 1 else []
        elif len(s["files"]) > 1 and rng.random() < benign_rate:
            paths = list(s["files"])
        else:
            paths = []
        for i, path in enumerate(paths):
            out.append({**s, "package_id": f"{s['package_id']}-f{i:04d}", "files": {path: s["files"][path]},
                        "payload_files": [path] if s["is_malicious"] else [], "granularity": "file"})
    return out
