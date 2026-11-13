"""Shared constants for the AI engine."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

ENGINE_ROOT: Final[Path] = Path(__file__).resolve().parent
PROJECT_ROOT: Final[Path] = ENGINE_ROOT.parent
ARTIFACT_DIR: Final[Path] = Path(os.environ.get("ARTIFACT_DIR", PROJECT_ROOT / "artifacts"))
SAMPLES_DIR: Final[Path] = Path(os.environ.get("SAMPLES_DIR", PROJECT_ROOT / "samples"))
AST_SERVICE_URL: Final[str] = os.environ.get("AST_SERVICE_URL", "http://127.0.0.1:8000")

RANDOM_STATE: Final[int] = 42
SUPPORTED_AST_SCHEMA: Final[int] = 1

BENIGN_LABEL: Final[str] = "benign"
KNOWN_ATTACK_TYPES: Final[tuple[str, ...]] = (
    "typosquatting",
    "malicious_build_hook",
    "backdoored_dependency",
    "dependency_confusion",
)
#: Withheld from supervised training to measure zero-day coverage.
NOVEL_ATTACK_TYPES: Final[tuple[str, ...]] = ("credential_stealer",)
CRITICAL_ATTACK_TYPES: Final[tuple[str, ...]] = (
    "malicious_build_hook",
    "backdoored_dependency",
    "dependency_confusion",
)

POPULAR_PACKAGES: Final[tuple[str, ...]] = (
    "requests", "numpy", "pandas", "django", "flask", "urllib3", "boto3", "setuptools", "colorama",
    "tensorflow", "scipy", "matplotlib", "cryptography", "pyyaml", "pillow", "click", "jinja2",
    "certifi", "idna", "attrs", "pytest", "selenium", "beautifulsoup4", "sqlalchemy", "paramiko",
)
INTERNAL_NAMESPACE_PREFIXES: Final[tuple[str, ...]] = ("acme-", "corp-", "internal-")
MAX_NAME_DISTANCE: Final[int] = 5

#: Registry/repository metadata accompanying each package, with neutral defaults.
METADATA_DEFAULTS: Final[dict[str, float]] = {
    "package_age_days": 365.0,
    "maintainer_account_age_days": 730.0,
    "num_maintainers": 2,
    "maintainer_changed": 0,
    "version_major": 1,
    "version_jump": 0,
    "downloads_weekly": 1000,
    "signed_commit_ratio": 0.7,
}
