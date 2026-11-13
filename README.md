# supply_chain_security

Offline supply chain attack detection for Python packages: static AST analysis, ML models, and a live admin dashboard. It uses no LLMs or external AI services. It is built from scikit-learn models, your local **AST Master** analyzer (`../ast_master`, mounted read-only), and a built-in AST extractor.

```
                         ┌──────────── telemetry events (HTTP, shared token) ────────────┐
                         │                                                                ▼
 package ─► ai_engine :8100 ──HTTP──► ast_detection :8000                      dashboard :8501 ──WS──► browser
            ├ Random Forest            ├ AST Master (63 rules)                  live pipeline, risky-node
            ├ Isolation Forest         ├ built-in node visitors                 code view, model scores,
            └ Hybrid scorer            └ 77 features + SHA-256 digest           health, test results
            ▲
 trainer ───┘ (one-shot: trains through ast_detection, writes .joblib to a shared volume)
```

## Run

```bash
docker compose up --build        # build → train → serve → run 75 tests → dashboard stays up
# or, detached with the test exit code (CI):
./run_pipeline.sh [--down]
```

Then open **http://127.0.0.1:8501** (bound to localhost only).

- `ast_detection`, `ai_engine`, `trainer` and `tests` sit on an `internal` network with no internet access.
- Only the dashboard joins a second network, so it can publish its port.
- Every container has a read-only filesystem, drops all Linux capabilities, and runs as a non-root user.

| Volume | Written by | Read by |
|---|---|---|
| `model_artifacts` | trainer | ai_engine, dashboard, tests |
| `test_results` (`junit.xml`) | tests | dashboard |
| `dashboard_data` (`events.jsonl`) | dashboard | dashboard (history survives restarts) |

Set `SCS_EVENT_TOKEN` to change the shared event-ingest token. Set `ASTMASTER_HOST_PATH` if AST Master is not at `../ast_master`.

## Train on your own real data

Training is fully local: your own scikit-learn models plus AST analysis. It calls no external AI service or API. Synthetic packages are used by default. To add real labelled packages, put them under `datasets/real/<label>/<package>`, where `<label>` is `benign` or an attack family. Each package can be a directory, a `.py` file, an archive or a JSON bundle; see [`datasets/real/README.md`](datasets/real/README.md).

```bash
docker compose up --build                                   # trainer picks up ./datasets/real automatically
REAL_DATA_HOST_PATH=/path/to/corpus docker compose up --build
python -m ai_engine.train --real-data datasets/real [--no-synthetic] [--quick]   # local
```

Real packages are split train/val/test per package. `training_report.json` adds `data_sources` (what was loaded or skipped) and `real_test_metrics` (scores on held-out real packages only).

## Training results

These results come from the currently served model, trained 2026-11-10 12:32 UTC in 19.9 s. The full report is `training_report.json` in the `model_artifacts` volume.

> **Read these numbers with care.** `datasets/real` was empty for this run, so every package was **synthetic**: 3,469 packages built from code templates. A perfect score here shows the models learned those templates. It does not prove they catch real attacks. Add real labelled packages and check `real_test_metrics` for that (`null` in this run).

**Data:** 3,469 packages: 2,835 benign; 136 each of `typosquatting`, `malicious_build_hook`, `backdoored_dependency`, `dependency_confusion`; and 90 `credential_stealer`, which is never trained on and appears only in the test set. Split: 2,081 train / 694 validation / 694 test. The models use 77 AST features plus registry metadata.

**Models:**

| Model | Settings |
|---|---|
| Random Forest | 400 trees, max depth 30, `sqrt` features, picked by a 10-setting random search with 3-fold CV; CV threat average precision 1.0 |
| Isolation Forest | 150 trees, `max_samples` 0.5 |
| Hybrid | decision threshold 0.925, AST weight 1.0, anomaly floor 0.988, static floor 0.34 |

**Test set** (694 packages: 567 benign, 127 malicious, including the unseen `credential_stealer` family):

| View | Precision | Recall | F1 | ROC-AUC | False-positive rate | TN / FP / FN / TP |
|---|---|---|---|---|---|---|
| AST rules only | 0.914 | 1.000 | 0.955 | 0.9998 | 2.1% | 555 / 12 / 0 / 127 |
| Random Forest only | 1.000 | 1.000 | 1.000 | 1.000 | 0.0% | 567 / 0 / 0 / 127 |
| Isolation Forest only | 0.929 | 0.622 | 0.745 | 0.979 | 1.1% | 561 / 6 / 48 / 79 |
| **Hybrid (served)** | **1.000** | **1.000** | **1.000** | **1.000** | **0.0%** | **567 / 0 / 0 / 127** |

**Detection rate per family:**

| Family | Count | AST only | RF only | IF only | Hybrid |
|---|---|---|---|---|---|
| backdoored_dependency | 28 | 100% | 100% | 50% | 100% |
| dependency_confusion | 27 | 100% | 100% | 89% | 100% |
| malicious_build_hook | 27 | 100% | 100% | 44% | 100% |
| typosquatting | 27 | 100% | 100% | 93% | 100% |
| credential_stealer (unseen) | 18 | 100% | 100% | 22% | 100% |
| benign (flagged in error) | 567 | 2.1% | 0% | 1.1% | 0% |

**Severity on the test set:** 565 NONE, 2 LOW, 2 MEDIUM, 125 CRITICAL.

**Layer verification: passed (all 5 checks).**
- AST features carry 89.7% of the Random Forest's importance (the minimum is 25%).
- Removing the AST layer drops the hybrid's ROC-AUC from 1.000 to 0.873 and its F1 from 1.000 to 0.000.
- Removing the ML layer drops the hybrid's F1 from 1.000 to 0.000.
- The hybrid beats AST rules alone: F1 1.000 vs 0.955, false-positive rate 0% vs 2.1%.

**Top Random Forest features:** `am_verdict_level`, `ast_module_level_dangerous`, `am_ctx_import`, `ast_recon_calls`, `am_risk_score`, `am_rule_env_exfiltration`, `am_rule_recon`, `am_sev_critical`, `am_rule_exfiltration`, `name_internal_pattern`.

## Upload Python files in the dashboard

Open http://127.0.0.1:8501. The **Scan Python files** panel offers three ways in:
- **Choose folder**: picks a whole project; subfolders are included.
- **Choose .py files**: picks individual files.
- **Drag and drop**: drop files or folders onto the panel.

**Python files only.** The browser keeps only `.py` files and reports how many others it ignored. The server enforces the same rule (`POST /api/scan/upload`) and also rejects unsafe paths such as `../`. Limits: 2 MB per file, 50 MB and 1,000 files per upload.

Each file goes through AST → Random Forest + Isolation Forest → hybrid score, exactly like `scanner.py`. Results appear in the panel and stream live in the pipeline view, where you can click a file to see its highlighted risky lines.

## Scan a directory (`scanner.py`)

This recursively audits every relevant file under a directory, `../supply_chain_lab` by default:

```bash
docker compose up -d --build              # start the stack (if it isn't running)
docker compose run --rm scanner           # scan ../supply_chain_lab via ai_engine -> ast_detection
#   LAB_HOST_PATH=/other/dir docker compose run --rm scanner
python scanner.py ../supply_chain_lab -o reports/scan_report.json [--all] [--fail-on malicious]   # local mode
```

**What it covers:**
- **Discovery:** a recursive walk that never follows symlinks.
- **Analysed through AST + AI:** Python files (including extensionless scripts with a Python shebang), install manifests (`setup.cfg`, `pyproject.toml`, `requirements*.txt`, `.pth`) and scripts (`.sh`, `.bat`, `.ps1`, `Makefile`).
- **Archives** (`.zip`, `.whl`, `.tar.gz`, ...) are read in memory, never extracted. Zip-slip members, zip bombs and nested archives are reported, not followed.
- **Recorded only:** binaries and other files, each with the reason it was skipped.

**Robustness:** files are scored in batches; if a batch fails, it is retried file by file. Syntax errors, invalid UTF-8, NUL bytes, unreadable files and corrupt archives each become their own row in the report, so one bad file never stops the scan.

**Output:**
- a CLI summary of per-project verdicts and flagged files, with line-level AST evidence and per-model scores;
- the full JSON report at `reports/scan_report.json`;
- the dashboard's **Directory scan** panel. In service mode, every file also streams through the live pipeline view.

**Verdicts:** MALICIOUS (block) / SUSPICIOUS (review) / BENIGN, plus NOT_ANALYZED or ERROR with a reason. Exit code 3 means `--fail-on` was triggered (for CI).

**Result on `supply_chain_lab`:** 391 files discovered, 147 analysed. The one injected payload, `attack_simulation_repo/src/requests/models.py:1187` (`exec(__import__("base64").b64decode(...))`, run at import), is **MALICIOUS**. The other 146 files, including both clean copies of `requests`, are **BENIGN**.

## Dashboard

- **Health strip**: AST service (AST Master version), AI engine (model loaded, packages scored), layer verification, test suite, event count.
- **Live pipeline**: each request moves through Submitted → AST parsing → AST analysed (n risky nodes) → AI scored. Each entry shows its verdict, risk, RF probability, IF percentile and AST verdict.
- **Assessment detail**:
  - per-layer contribution bars;
  - the risk *without* the AST layer;
  - the per-prediction verification checks;
  - **the parsed source with risky AST nodes highlighted** (`exec`, `dynamic_import`, `network`, `install_hook`, ...);
  - AST Master findings and the top model factors.
- **Submit**: one-click bundled samples, or paste your own `setup.py` and module with a metadata preset.
- **Event stream**: raw, request-correlated events from every container.

Package source is untrusted, so the UI renders all of it with `textContent` and never `innerHTML`.

## APIs

| Service | Endpoints |
|---|---|
| ast_detection | `GET /health`, `POST /analyze`, `POST /analyze/batch` |
| ai_engine | `GET /health`, `POST /assess` (`{"packages": [{name, files, metadata?}]}`), `POST /reload` |
| dashboard | `GET /`, `WS /ws`, `POST /api/events`, `GET /api/events`, `GET /api/health`, `POST /api/submit`, `GET/POST /api/samples[/{id}]` |

## Tests (`pytest`, 75)

- `test_ast_engine.py`: the node visitors, AST Master loading and fallback, risky-node locations and severities, verdicts on the samples, and static accuracy on a generated corpus.
- `test_ai_models.py`: the Random Forest and Isolation Forest units, the fusion policy (gating, monotonicity, escalation), the feature pipeline and ablation, holdout accuracy, and artifact tamper detection.
- `test_real_data.py`: the real-data loader (directories, files, bundles, archives; bad labels, duplicates and label conflicts), the per-package split with novel families held out for testing, and an end-to-end training run on real packages.
- `test_integration.py`: the API contracts of all three services; one request ID flowing through the dashboard, AI engine and AST service; the WebSocket live stream; end-to-end sample submission through the dashboard; and *backdoor injection flips the verdict with identical metadata*.

In Docker the tests hit the real containers. Locally, `pip install -r requirements.txt && pytest` starts the same three servers in-process.

## Local development (no Docker)

```bash
python -m dashboard.app                                  # :8501
EVENT_SINK_URL=http://127.0.0.1:8501/api/events python -m ast_detection.server
EVENT_SINK_URL=http://127.0.0.1:8501/api/events python -m ai_engine.train --quick
EVENT_SINK_URL=http://127.0.0.1:8501/api/events python -m ai_engine.server
```

## How the verdict is made

```
risk = 1 - (1 - p_rf) * (1 - a_iforest_gated) * (1 - w * s_ast_gated)
```

Each gate is a false-positive budget calibrated on benign validation data. The weight `w` is tuned but never zero.

- **Escalation**: a high-impact family at moderate Random Forest confidence can be escalated, but only to MEDIUM / QUARANTINE_REVIEW. Hard blocks require the fused risk itself to cross the decision threshold.
- **Training gate**: models are saved only if AST features carry ≥ 25% of the Random Forest's importance, ablating the AST layer *and* ablating the ML layer each hurt detection, and the hybrid is no worse than static analysis alone.

## Samples (`samples/`)

The malicious samples are inert mocks: they use TEST-NET IPs and are only ever parsed, never executed.

| Package | Kind | Verdict |
|---|---|---|
| `tinyjson` | benign | ALLOW |
| `fastgeo` | benign, downloads binaries during install | ALLOW (static analysis alone flags it) |
| `colorlogx` | backdoored dependency | CRITICAL · BLOCK |
| `reqeusts` | typosquat that exfiltrates the environment at install | CRITICAL · BLOCK |
