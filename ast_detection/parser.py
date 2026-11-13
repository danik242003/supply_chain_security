"""Discovery and wrapper for the local AST Master analyzer (``astmaster``).

AST Master is vendored in this project at ``vendor/ast_master`` (in Docker it is
baked into the image at ``/opt/ast_master``). This module finds it,
imports only its side-effect-free security layer, and exposes a small, stable
interface. If it cannot be found or imported, :class:`AstMasterParser` reports
``available = False`` and the service keeps working with the built-in extractor.

Search order for the directory that contains the ``astmaster`` package:

1. ``$ASTMASTER_PATH``
2. ``/opt/ast_master``
3. ``<project>/vendor/ast_master`` (vendored copy)
4. ``<project parent>/ast_master`` (sibling of this project on the Desktop)
5. ``~/Desktop/ast_master``
"""

from __future__ import annotations

import importlib
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType
from typing import Any

logger = logging.getLogger(__name__)

ENV_VAR = "ASTMASTER_PATH"


def candidate_roots() -> list[Path]:
    """Directories that may contain the ``astmaster`` package, in priority order."""
    roots: list[Path] = []
    if os.environ.get(ENV_VAR):
        roots.append(Path(os.environ[ENV_VAR]).expanduser())
    roots.append(Path("/opt/ast_master"))
    roots.append(Path(__file__).resolve().parents[1] / "vendor" / "ast_master")
    roots.append(Path(__file__).resolve().parents[2] / "ast_master")
    roots.append(Path.home() / "Desktop" / "ast_master")
    return roots


def discover_astmaster() -> Path | None:
    """Return the first root holding ``astmaster/security.py``, or ``None``."""
    for root in candidate_roots():
        if (root / "astmaster" / "security.py").is_file():
            return root.resolve()
    return None


#: astmaster scanner to use for each kind of file, chosen by file name.
def _handler_name(path: str) -> str | None:
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith((".py", ".pyw")):
        return "scan_python"
    if name.endswith(".pth"):
        return "scan_pth"
    if name == "pyproject.toml":
        return "scan_pyproject"
    if name == "setup.cfg":
        return "scan_setup_cfg"
    if name.endswith(".txt") and "requirement" in name:
        return "scan_requirements"
    if name.endswith((".sh", ".bash", ".zsh", ".bat", ".cmd", ".ps1")) or name in ("makefile", "gnumakefile"):
        return "scan_script"
    return None


@dataclass
class AstMasterFileResult:
    """astmaster output for a single file.

    Attributes:
        path: Package-relative path.
        status: astmaster parse status (``ok``, ``unparsed``, ``too-complex``).
        kind: ``install``, ``module`` or ``test`` (astmaster's own classification).
        findings: Raw ``astmaster.security.Finding`` objects.
        structure: Structural counts (functions, loops, threads, ...).
    """

    path: str
    status: str
    kind: str
    findings: list[Any] = field(default_factory=list)
    structure: dict[str, int] = field(default_factory=dict)


class AstMasterParser:
    """Thin adapter over ``astmaster.security``.

    Args:
        root: Directory containing the ``astmaster`` package; discovered if ``None``.
        required: Raise instead of degrading gracefully when it cannot be loaded.
    """

    def __init__(self, root: str | Path | None = None, required: bool = False) -> None:
        self.root: Path | None = Path(root).resolve() if root else discover_astmaster()
        self.error: str | None = None
        self._security: ModuleType | None = None
        if self.root is None:
            self.error = "astmaster not found (set ASTMASTER_PATH)"
        elif not (self.root / "astmaster" / "security.py").is_file():
            self.error = f"no astmaster package under {self.root}"
        else:
            try:
                if str(self.root) not in sys.path:
                    sys.path.insert(0, str(self.root))
                self._security = importlib.import_module("astmaster.security")
            except Exception as exc:  # any import failure must degrade, not crash
                self.error = f"failed to import astmaster: {exc!r}"
        if self._security is None:
            if required:
                raise RuntimeError(self.error)
            logger.warning("AST Master unavailable: %s; using built-in extractor only", self.error)
        else:
            logger.info("AST Master loaded from %s (rules v%s)", self.root, self.rules_version)

    @property
    def available(self) -> bool:
        """Whether astmaster was imported successfully."""
        return self._security is not None

    @property
    def rules_version(self) -> int | None:
        """astmaster's ``RULES_VERSION``."""
        return getattr(self._security, "RULES_VERSION", None)

    @property
    def rule_names(self) -> list[str]:
        """All rule identifiers astmaster can emit."""
        return sorted(getattr(self._security, "RULES", {}))

    def backend_info(self) -> dict[str, Any]:
        """Description of the loaded backend, for health checks and reports."""
        return {
            "name": "astmaster",
            "available": self.available,
            "root": str(self.root) if self.root else None,
            "rules_version": self.rules_version,
            "n_rules": len(self.rule_names),
            "error": self.error,
        }

    def analyze_file(self, path: str, data: bytes) -> AstMasterFileResult | None:
        """Scan one file. Returns ``None`` when astmaster is unavailable or the file type is unsupported."""
        if self._security is None:
            return None
        handler = _handler_name(path)
        if handler is None:
            return None
        sec = self._security
        signals = getattr(sec, handler)(data)
        findings = sec.rate_file(path, signals)
        return AstMasterFileResult(
            path=path,
            status=signals.status,
            kind=sec.file_kind(path),
            findings=findings,
            structure=dict(signals.structure),
        )

    def summarize(self, findings: list[Any]) -> dict[str, Any]:
        """astmaster's package-level triage score (0-100) and verdict."""
        if self._security is None:
            return {"risk_score": None, "verdict": None}
        return {
            "risk_score": int(self._security.risk_score(findings)),
            "verdict": str(self._security.verdict_for(findings)),
        }
