# Async Scan Jobs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single long `POST /scanner/run` request with a background job the extension polls every 2 s, so no request outlives Chrome's 30 s service-worker fetch rule, the activity console fills live, and Stop cancels the backend scan.

**Architecture:** The engine publishes `module_log`/`current_module` into the scan context as it runs; a `JobStore` runs `engine.run` on a daemon thread and snapshots that context; three Flask routes expose start/status/cancel; a pure, dependency-injected `pollScanJob` in the extension drives the loop and is unit-tested with `node --test`; the service worker wires it to `fetch` and `chrome.storage.session`.

**Tech Stack:** Python 3 / Flask (threaded) / pytest + pytest-mock; Chrome MV3 ES-module service worker; Node 24 built-in `node --test` (no new dependency).

**Spec:** `docs/superpowers/specs/2026-11-04-async-scan-jobs-design.md`

## Global Constraints

- Constants, exactly: `MAX_RUNNING = 2`, `RETENTION_S = 900`, `MAX_STORED = 50`; poll `intervalMs = 2000`; per-call fetch timeout 5000 ms; `maxConsecutiveErrors = 3`; extension `maxDurationMs = (budget + 30) * 1000`; up to 5 extra polls after a timeout-cancel.
- Job statuses, exactly: `running`, `done`, `cancelled`, `error`. Skip reason when cancelled: `"cancelled"` (otherwise `"time_budget"` as today).
- HTTP: `POST /scanner/jobs` → 202 `{"jobId"}` | 400 | 429; `GET /scanner/jobs/<id>` → 200 `{"jobId","status","currentModule","moduleLog","elapsedMs"[, "result"][, "error"]}` | 404; `DELETE /scanner/jobs/<id>` → 202 `{"jobId","status":"cancelling"}` | 404. `result` is present only for `done`/`cancelled` and equals `_build_run_response(findings, context)`.
- `POST /scanner/run` keeps its exact response; every existing test passes unchanged (195 on master `aa8c30f`).
- Client-sent `deadline`, `cancelled`, `current_module` are dropped; a non-dict `context` becomes `{}` on both scan endpoints.
- Python: `C:\vulnscan-windows\backend\.venv\Scripts\python.exe -m pytest backend/tests/ -q -p no:cacheprovider` from the worktree root. Host has 3.5 GB RAM: one command at a time.

## Review Focus

1. A job snapshot read while the run thread appends to `module_log` must never raise or return a half-built entry (copy the list under the store's lock; entries are appended whole) — Task A test reads mid-run.
2. A third concurrent `POST /scanner/jobs` gets 429 and starts nothing; once one job finishes, a new one is accepted — Task A (store) + Task B (route) tests.
3. Cancel of an already-finished job is a no-op returning 202 with the final status unchanged — Task A test.
4. The poller never delivers the same `moduleLog` entry twice, including across a failed poll followed by a successful one — Task C test.
5. Stop pressed mid-scan sends `DELETE` and the scan still ends with the partial findings saved to history, not an empty result — Task D manual/browser check.

---

### Task A: Engine progress publication + JobStore

**Files:** Modify `backend/scanner/core/engine.py` (`run`); Create `backend/scanner/core/jobs.py`; Test `backend/tests/test_engine.py`, Create `backend/tests/test_jobs.py`.

**Interfaces — Produces:**
- `class TooManyJobs(Exception)`; `class JobStore` with `create(run_fn, target, context, enabled, crawl) -> str`, `snapshot(job_id) -> Optional[dict]`, `cancel(job_id) -> bool`; module-level constants from Global Constraints; snapshot keys `status, current_module, module_log, findings, context, error, elapsed_ms` (`findings`/`context` only when finished, else `None`).
- Engine: `context["module_log"]` is the live list from loop start; `context["current_module"]` set per module, `None` after; cancelled skip reason.

- [ ] **Step 1: Failing tests.** `test_engine.py`: `test_module_log_visible_during_run` (module B's `scan` asserts `context["module_log"][0]["module"] == "a"`), `test_current_module_set_during_and_cleared_after`, `test_cancelled_skip_reason`. `test_jobs.py`: `test_job_visible_mid_run` (fake `run_fn` appends an entry to `context["module_log"]`, then waits on a `threading.Event`; `snapshot` shows status `running` and the entry), `test_job_done_returns_findings_and_context`, `test_job_error_keeps_message`, `test_cancel_sets_deadline_and_flag_and_status` (fake run checks the flag, returns partial findings ⇒ status `cancelled`), `test_cancel_finished_job_is_noop`, `test_third_concurrent_job_raises_too_many`, `test_finished_job_purged_after_retention` (patch the store's clock), `test_unknown_job_snapshot_is_none`. Release every Event in a `finally` so no test leaves a thread blocked.
- [ ] **Step 2: Run** both files — new tests FAIL.
- [ ] **Step 3: Implement.** Engine: assign `context["module_log"] = module_log` before the loop (keep the existing end-of-run assignment and `self.last_module_log` as they are); set/clear `current_module`; choose the skip reason from `context.get("cancelled")`. JobStore: one `threading.Lock`; daemon `threading.Thread`; status transitions under the lock; `snapshot` copies `module_log` under the lock; clock via an injectable `time.monotonic` so tests can patch it.
- [ ] **Step 4: Run** the two files, then the full suite — PASS.
- [ ] **Step 5: Commit** `feat(scanner): background scan jobs with live progress and cancel`

### Task B: Job routes

**Files:** Modify `backend/routes/scanner_engine.py`; Test `backend/tests/test_scanner_engine_routes.py`.

**Interfaces — Consumes:** Task A's `JobStore`, `TooManyJobs`. **Produces:** `_build_run_response(findings, context) -> dict`; the three endpoints per Global Constraints; one module-level `JobStore` instance used by the routes (tests may replace it).

- [ ] **Step 1: Failing tests** (follow the file's existing Flask/engine-mocking style; use a fake engine whose `run` is controllable): `test_run_response_builder_matches_run_endpoint`, `test_run_with_null_context_is_not_500`, `test_jobs_post_returns_202_and_id`, `test_jobs_post_without_target_400`, `test_jobs_post_429_when_too_many`, `test_jobs_get_running_then_done_with_result` (result equals `_build_run_response` of the same findings/context), `test_jobs_get_unknown_404`, `test_jobs_delete_202_and_unknown_404`, `test_jobs_drop_client_control_keys` (client `deadline`/`cancelled`/`current_module` never reach the engine context).
- [ ] **Step 2: Run** — new tests FAIL.
- [ ] **Step 3: Implement** the extraction (`/scanner/run` body unchanged in output), the context sanitizer shared by both endpoints, and the three routes. `moduleLog` in GET uses the existing `_module_log_entry`.
- [ ] **Step 4: Run** the file, then the full suite — PASS.
- [ ] **Step 5: Commit** `feat(api): POST/GET/DELETE /scanner/jobs for polled scans`

### Task C: Pure job poller + node tests

**Files:** Create `extension/src/utils/job-poller.js`, `extension/tests/job-poller.test.mjs`; Modify `extension/package.json` (`"test": "node --test tests/"`).

**Interfaces — Produces:** `export async function pollScanJob({ startJob, getJob, cancelJob, sleep, now, onProgress, onTick, intervalMs = 2000, maxDurationMs, maxConsecutiveErrors = 3 }) -> Promise<{ status, result, moduleLog }>` exactly as the spec describes. `startJob()` → `{ jobId }`; `getJob(jobId)` → the GET body; `cancelJob(jobId)` → anything.

- [ ] **Step 1: Failing tests** with `node:test` + `node:assert/strict`, fake I/O and a fake clock: `delivers each moduleLog entry once across polls`, `no duplicate after a failed poll then a success`, `stops and returns result on done`, `returns partial result on cancelled`, `returns error status on error`, `timeout cancels once then returns the partial result`, `gives up after 3 consecutive failures and cancels best-effort`, `calls onTick every poll with the job id`.
- [ ] **Step 2: Run** `node --test extension/tests/` — FAIL (module missing).
- [ ] **Step 3: Implement** `pollScanJob` (no `chrome.*`, no globals; ES module).
- [ ] **Step 4: Run** `node --test extension/tests/` — PASS; `node --check extension/src/utils/job-poller.js`.
- [ ] **Step 5: Commit** `feat(extension): pure scan-job poller with node tests`

### Task D: Service worker integration

**Files:** Modify `extension/src/background/service-worker.js` (`runActiveModules`, `startScan` after it, `stopScan`).

**Interfaces — Consumes:** Task B endpoints; Task C `pollScanJob`.

- [ ] **Step 1: Implement** per the spec's "Service worker" section: import `pollScanJob`; three `fetch` helpers (5000 ms timeout each) for start/get/delete; `maxDurationMs = (budget + 30) * 1000` using the existing `TIME_BUDGET_FOR_PROFILE`; `onProgress` → `broadcastMessage({ type: "MODULE_LOG", payload: newEntries })`; `onTick` → `chrome.storage.session.set({ activeScanJob: { jobId, at: Date.now() } })`; store `currentScan.backendJobId`; map `result` to `{ findings, discovery, moduleLog }` as today; on `error`/no result return the same empty shape as today; remove the post-run full `MODULE_LOG` re-broadcast in `startScan`; `stopScan` fires `DELETE` for `currentScan.backendJobId` (best-effort, not awaited past 5 s) before `finalizeScan`; remove `activeScanJob` from session storage when done.
- [ ] **Step 2: Verify** `node --check` on the service worker; `node --test extension/tests/` still green; then a live check against the real backend: start the backend from the worktree, `curl` a `POST /scanner/jobs` on a local target, poll `GET` until `done`, confirm the `moduleLog` grows across polls and `result` has the `/scanner/run` shape; `DELETE` mid-run ⇒ status `cancelled` with partial result. Record the commands and outputs in the report.
- [ ] **Step 3: Commit** `feat(extension): run active scans as polled backend jobs, cancel on stop`
