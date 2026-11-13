"""Read real packages (directories, single files, JSON bundles) into analysis payloads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ai_engine.config import METADATA_DEFAULTS

#: Files sent to the AST service: Python sources plus install/dependency manifests.
ANALYZED_SUFFIXES = (".py", ".pyw", ".pth")
ANALYZED_NAMES = ("setup.cfg", "pyproject.toml", "requirements.txt")
SKIP_DIRS = frozenset({".git", "__pycache__", ".venv", "venv", "node_modules", ".tox", "build", "dist"})
METADATA_FILE = "package_meta.json"
MAX_FILE_BYTES = 2 * 1024 * 1024


class PackageLoadError(ValueError):
    """Raised when a package path or bundle is unusable."""


def _wanted(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(ANALYZED_SUFFIXES) or name in ANALYZED_NAMES or ("requirement" in name and name.endswith(".txt"))


def load_package_dir(path: str | Path, name: str | None = None) -> dict[str, Any]:
    """Collect analysable files from a package directory (or a single file).

    ``package_meta.json`` in the directory, if present, supplies registry metadata
    (and optionally ``name``). Symlinks are not followed.

    Returns:
        ``{"name", "files": {relative_path: source}, "metadata": {...}, "source_path"}``.
    """
    root = Path(path)
    if not root.exists():
        raise PackageLoadError(f"{root} does not exist")
    files: dict[str, str] = {}
    meta: dict[str, Any] = {}
    if root.is_file():
        files[root.name] = root.read_text(encoding="utf-8", errors="replace")
        pkg_name = name or root.stem
    else:
        meta_path = root / METADATA_FILE
        if meta_path.is_file():
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        for file in sorted(root.rglob("*")):
            rel = file.relative_to(root)
            if any(part in SKIP_DIRS for part in rel.parts) or file.is_symlink() or not file.is_file():
                continue
            if _wanted(file) and file.stat().st_size <= MAX_FILE_BYTES:
                files[rel.as_posix()] = file.read_text(encoding="utf-8", errors="replace")
        pkg_name = name or meta.pop("name", None) or root.name
    meta.pop("name", None)
    if not files:
        raise PackageLoadError(f"no analysable files under {root}")
    return {"name": pkg_name, "files": files, "metadata": normalize_metadata(meta), "source_path": str(root)}


def normalize_metadata(meta: dict[str, Any] | None) -> dict[str, float]:
    """Fill missing metadata with neutral defaults and coerce to float."""
    out: dict[str, float] = {}
    for key, default in METADATA_DEFAULTS.items():
        try:
            out[key] = float((meta or {}).get(key, default))
        except (TypeError, ValueError):
            out[key] = float(default)
    return out


def load_bundle(path: str | Path) -> list[dict[str, Any]]:
    """Load ``{"packages": [{"name", "files", "metadata"?}, ...]}`` (or a bare list) from JSON."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    packages = payload.get("packages") if isinstance(payload, dict) else payload
    if not isinstance(packages, list) or not packages:
        raise PackageLoadError("bundle must contain a non-empty 'packages' list")
    out = []
    for p in packages:
        if not isinstance(p, dict) or not isinstance(p.get("name"), str) or not isinstance(p.get("files"), dict):
            raise PackageLoadError("each package needs 'name' (str) and 'files' (object)")
        out.append({"name": p["name"], "files": p["files"], "metadata": normalize_metadata(p.get("metadata"))})
    return out
