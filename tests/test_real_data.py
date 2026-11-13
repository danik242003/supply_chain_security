"""Real-data loader and its wiring into training (offline: packages are parsed, never executed)."""

from __future__ import annotations

import io
import json
import shutil
import tarfile
from pathlib import Path

import pytest

from ai_engine.config import SAMPLES_DIR
from ai_engine.data.loader import PackageLoadError
from ai_engine.data.real_dataset import file_level_samples, load_labeled_dataset, split_by_package

BENIGN_SRC = 'def add(a, b):\n    """Sum."""\n    return a + b\n'


def _pkg(root: Path, label: str, name: str, files: dict[str, str], meta: dict | None = None) -> Path:
    d = root / label / name
    for rel, src in files.items():
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text(src, encoding="utf-8")
    if meta is not None:
        (d / "package_meta.json").write_text(json.dumps(meta), encoding="utf-8")
    return d


def test_loads_dirs_files_bundles_and_archives(tmp_path: Path) -> None:
    _pkg(tmp_path, "benign", "alpha", {"setup.py": "from setuptools import setup\nsetup(name='alpha')\n",
                                       "alpha/__init__.py": BENIGN_SRC},
         {"name": "alpha", "downloads_weekly": 5000})
    (tmp_path / "benign" / "single.py").write_text(BENIGN_SRC + "\n# single\n", encoding="utf-8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = (BENIGN_SRC + "\n# archived\n").encode()
        info = tarfile.TarInfo("gamma-1.0/gamma/__init__.py")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    (tmp_path / "benign" / "gamma-1.0.tar.gz").write_bytes(buf.getvalue())
    (tmp_path / "typosquatting").mkdir()
    (tmp_path / "typosquatting" / "bundle.json").write_text(json.dumps({"packages": [
        {"name": "reqeust", "files": {"setup.py": "import os\nos.system('curl x')\n"},
         "payload_files": ["setup.py"]}]}), encoding="utf-8")

    samples, skipped = load_labeled_dataset(tmp_path)
    by_name = {s["name"]: s for s in samples}
    assert set(by_name) == {"alpha", "single", "gamma-1.0", "reqeust"}
    assert skipped == []
    assert by_name["alpha"]["metadata"]["downloads_weekly"] == 5000.0
    assert by_name["gamma-1.0"]["files"] == {"gamma/__init__.py": BENIGN_SRC + "\n# archived\n"}
    assert by_name["reqeust"]["attack_type"] == "typosquatting" and by_name["reqeust"]["is_malicious"] == 1
    assert by_name["reqeust"]["payload_files"] == ["setup.py"]
    assert all(s["source"] == "real" for s in samples)


def test_skips_bad_labels_duplicates_and_conflicts(tmp_path: Path) -> None:
    files = {"x/__init__.py": BENIGN_SRC}
    _pkg(tmp_path, "benign", "one", files)
    _pkg(tmp_path, "backdoored_dependency", "three", files)  # loads first (sorted label dirs)
    _pkg(tmp_path, "backdoored_dependency", "three_dup", files)  # duplicate, same label
    # benign/one: same code under a different label -> conflict
    _pkg(tmp_path, "Bad-Label", "four", {"y.py": BENIGN_SRC})
    (tmp_path / "benign" / "notes.txt").write_text("hello", encoding="utf-8")
    samples, skipped = load_labeled_dataset(tmp_path)
    assert [s["name"] for s in samples] == ["three"]  # label dirs load in sorted order
    reasons = " | ".join(s["reason"] for s in skipped)
    assert "label folder" in reasons and "label conflict" in reasons and "duplicate" in reasons
    assert "unsupported entry" in reasons


def test_missing_dir_raises(tmp_path: Path) -> None:
    with pytest.raises(PackageLoadError):
        load_labeled_dataset(tmp_path / "nope")


def test_split_is_per_package_and_novel_is_test_only(tmp_path: Path) -> None:
    for i in range(10):
        _pkg(tmp_path, "benign", f"b{i}", {"a.py": BENIGN_SRC + f"# {i}\n", "b.py": BENIGN_SRC + f"# b{i}\n"})
    for i in range(5):
        _pkg(tmp_path, "credential_stealer", f"c{i}", {"c.py": f"open('/root/.ssh/id_rsa')  # {i}\n"})
    _pkg(tmp_path, "rare_family", "r0", {"r.py": "eval(input())\n"})
    samples, _ = load_labeled_dataset(tmp_path)
    splits = split_by_package(samples, seed=1)
    assert [s["attack_type"] for s in splits["test"]].count("credential_stealer") == 5
    assert all(s["attack_type"] != "credential_stealer" for s in splits["train"] + splits["val"])
    assert [s["name"] for s in splits["train"] if s["attack_type"] == "rare_family"] == ["r0"]
    assert {len([s for s in splits[k] if s["attack_type"] == "benign"]) for k in ("val", "test")} == {2}

    singles = file_level_samples(splits["train"], seed=1, benign_rate=1.0)
    train_groups = {s["group_id"] for s in splits["train"]}
    assert singles and all(s["group_id"] in train_groups and len(s["files"]) == 1 for s in singles)


def test_training_with_real_data(tmp_path: Path, stack) -> None:
    """End to end: real packages flow through the AST service into training and the report."""
    from ai_engine.train import TrainingConfig, train_pipeline

    real = tmp_path / "real"
    labels = {"benign_pkg": "benign", "gray_native_pkg": "benign",
              "malicious_backdoor": "backdoored_dependency", "typosquat_reqeusts": "typosquatting"}
    for sample, label in labels.items():
        shutil.copytree(SAMPLES_DIR / sample, real / label / sample)
    report = train_pipeline(TrainingConfig(artifact_dir=tmp_path / "out", ast_url=stack.ast_url, n_benign=300,
                                           seed=3, tune=False, real_data_dir=real))
    src = report["data_sources"]
    assert src["real_packages"] == 4 and src["real_skipped"] == []
    assert src["real_classes"] == {"benign": 2, "backdoored_dependency": 1, "typosquatting": 1}
    assert src["real_split_packages"]["train"] == 4  # < 3 per label: all go to training
    assert (tmp_path / "out" / "manifest.json").is_file()
