# Real training data

Put labelled real-world packages here. The trainer mounts this folder read-only at `/data/real`. You can point it somewhere else with `REAL_DATA_HOST_PATH=/path docker compose up --build`. Locally, run `python -m ai_engine.train --real-data datasets/real`.

Training runs fully offline on your machine: your own scikit-learn models, AST analysis and data. No external AI service or API is called. Packages are only **parsed**, never executed, imported or extracted.

```
datasets/real/
  benign/                     clean packages (popular libraries, your own code, ...)
    requests-2.32.3/          package directory
    tinyjson.tar.gz           archive (.zip .whl .egg .tar.gz .tgz .tar .tar.bz2 .tar.xz), read in memory
    util.py                   single file
  backdoored_dependency/      folder name = label: benign or any family, [a-z][a-z0-9_]*
    colorlogx/
      package_meta.json       optional: registry metadata + "payload_files"
      ...
  typosquatting/
    bundle.json               {"packages": [{"name", "files": {path: source}, "metadata"?, "payload_files"?}]}
```

**`package_meta.json`** (all fields optional; missing ones get neutral defaults):

```json
{"name": "colorlogx", "package_age_days": 1300, "maintainer_account_age_days": 9, "num_maintainers": 2,
 "maintainer_changed": 1, "version_major": 1, "version_jump": 0, "downloads_weekly": 36000,
 "signed_commit_ratio": 0.12, "payload_files": ["colorlogx/__init__.py"]}
```

`payload_files` names the files that carry the malicious code. Each one also becomes a single-file training sample, which matches how `scanner.py` and the dashboard score files one at a time.

**Rules:**
- Packages are split train/val/test **per package and per label** (60/20/20). Families with fewer than 3 packages go to training only.
- `credential_stealer` (see `NOVEL_ATTACK_TYPES` in `ai_engine/config.py`) is never trained on. It is test-only and measures zero-day coverage.
- Identical packages are dropped. If the same package appears under two labels, the second one is skipped and reported.
- Encrypted archives (e.g. the password-protected zips in public malware datasets) must be decrypted first. Symlinks are ignored.
- Synthetic data is still included by default. Add `--no-synthetic` to train on this folder only; it then needs enough benign and attack packages for every split.

`training_report.json` → `data_sources` shows what was loaded and skipped. `real_test_metrics` shows performance on held-out **real** packages only, which is the number to trust.

This folder is listed in `.dockerignore`, so malware samples are never copied into images.
