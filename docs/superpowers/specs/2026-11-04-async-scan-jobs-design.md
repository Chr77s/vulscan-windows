# Async scan jobs — no single long request, live progress, real cancel

Date: 2026-11-04. Status: approved (user chose this as the next round: "construis les jobs async d'abord, puis pousse tout à la fin").

## Problem

- The extension's service worker calls `POST /scanner/run` and waits for one response that can take the whole scan budget (45-150 s).
- Chrome documents that it stops an extension service worker "When a fetch() response takes more than 30 seconds to arrive" (developer.chrome.com, service-worker lifecycle, read 2026-11-04). The page does not say whether this covers fetches the worker itself makes; if it does, every active scan slower than 30 s loses all its results. This predates the scan-budget round (it already applied at 60 s).
- While the scan runs the user sees nothing from the backend: the per-module activity console only fills when the single response arrives.
- `STOP_SCAN` finalizes the scan in the extension, but the backend keeps scanning the target until it finishes.

## Goal

No request between the extension and the backend ever takes more than a few seconds. The activity console fills module by module while the scan runs. Stop really stops the backend scan, and still returns what was found so far.

## Design

### Backend

**Engine publishes progress into the context it already owns** (`backend/scanner/core/engine.py`):
- `context["module_log"]` is assigned the run's `module_log` list at the start of the module loop (same list object, appended in place), instead of only at the end. Readers on another thread see entries as they are appended.
- `context["current_module"]` is set to the module name before each module runs, and to `None` after the loop.
- When `context.get("cancelled")` is true, the skip reason is `"cancelled"` instead of `"time_budget"`.

**Job store** — new `backend/scanner/core/jobs.py`, class `JobStore`:
- `create(run_fn, target, context, enabled, crawl) -> str` starts a daemon thread calling `run_fn(target, context, enabled, crawl)` (the route passes `engine.run`) and returns a job id (`uuid4().hex`). Raises `TooManyJobs` if `MAX_RUNNING = 2` jobs are already running.
- `snapshot(job_id) -> dict | None` returns `{"status", "current_module", "module_log" (a copy), "findings" (only when finished), "context" (only when finished), "error", "elapsed_ms"}`. Status is one of `running`, `done`, `cancelled`, `error`.
- `cancel(job_id) -> bool`: sets `context["cancelled"] = True` and `context["deadline"] = time.monotonic()`, which reuses the scan-budget machinery: `http.send` refuses at once and every remaining module is skipped. The run still ends normally, returning its partial findings; the status becomes `cancelled`.
- Retention: finished jobs are kept `RETENTION_S = 900` seconds, at most `MAX_STORED = 50` jobs (oldest finished dropped first); purge runs on `create` and `snapshot`. All state behind one lock.
- A run that raises sets status `error` and keeps the message.

**Routes** (`backend/routes/scanner_engine.py`):
- Extract the existing `/scanner/run` response body into `_build_run_response(findings, context) -> dict` and reuse it, so a finished job's `result` is byte-for-byte the `/scanner/run` shape.
- Trust boundary: a missing or non-dict `context` becomes `{}` (today `"context": null` gives HTTP 500); `deadline`, `cancelled` and `current_module` sent by a client are dropped.
- `POST /scanner/jobs` → `202 {"jobId": id}`; `400` without `target`; `429 {"error": ...}` when `TooManyJobs`.
- `GET /scanner/jobs/<id>` → `200 {"jobId", "status", "currentModule", "moduleLog": [camelCase entries as in /scanner/run], "elapsedMs", "result": <_build_run_response> when status is done or cancelled, "error": str when status is error}`; `404` for an unknown or purged id.
- `DELETE /scanner/jobs/<id>` → `202 {"jobId", "status": "cancelling"}`; `404` unknown.
- `POST /scanner/run` stays as it is (tests and any other caller keep working).

### Extension

**Pure poller** — new `extension/src/utils/job-poller.js`, exported `pollScanJob({ startJob, getJob, cancelJob, sleep, now, onProgress, onTick, intervalMs = 2000, maxDurationMs, maxConsecutiveErrors = 3 }) -> Promise<{ status, result, moduleLog }>`:
- `startJob()` resolves `{ jobId }`; then loop: `await sleep(intervalMs)`, `getJob(jobId)`; call `onProgress(newEntries)` with only the `moduleLog` entries not delivered before; call `onTick(jobId)` every iteration.
- Stops when status is `done`, `cancelled` or `error`. If `now() - start > maxDurationMs`, calls `cancelJob(jobId)` once and keeps polling up to 5 more times for the partial result.
- A failing `getJob` is retried; after `maxConsecutiveErrors` consecutive failures it gives up, calls `cancelJob` best-effort, and resolves `{ status: "error", result: null, moduleLog: <delivered so far> }`.
- All I/O is injected, so it runs in Node.

**Service worker** (`extension/src/background/service-worker.js`, `runActiveModules`):
- Uses `pollScanJob` with `fetch` calls to the three job endpoints (each with `AbortSignal.timeout(5000)`), `maxDurationMs = (budget + 30) * 1000`, `onProgress` broadcasting `MODULE_LOG` with the new entries only, and `onTick` writing `chrome.storage.session.set({ activeScanJob: { jobId, at: Date.now() } })`. That is an extension API call every 2 s, which resets the service worker's idle timer, and leaves the job id recoverable.
- Stores the job id on `currentScan.backendJobId`; `stopScan()` sends `DELETE` for it (best-effort) before finalizing.
- Returns `{ findings, discovery, moduleLog }` from `result` exactly as today, so the rest of the pipeline (enrichment, triage, history, exports) is untouched.
- `startScan` no longer re-broadcasts the full `moduleLog` after `runActiveModules` (the entries were already streamed). `SCAN_COMPLETED` still rebuilds the console from the full log, so the final view is unchanged.
- `chrome.storage.session.remove("activeScanJob")` when the job finishes.

## Error handling

- Backend unreachable at start: same as today (no active findings, console warning).
- Lost polls: up to 3 consecutive, then give up as above.
- A job whose client vanished still finishes within its budget and is purged after `RETENTION_S`.

## Testing

Backend (pytest, TDD): `test_jobs.py` — a running job is visible mid-run (a fake `run_fn` paused on a `threading.Event` appends to `context["module_log"]`; the snapshot shows the entry before the run ends); done/cancelled/error lifecycles; `TooManyJobs` at the third concurrent job; purge after `RETENTION_S` with a patched clock; unknown id → `None`. `test_engine.py` — another module sees the first module's entry in `context["module_log"]` during the run; `current_module` is set during and `None` after; cancelled ⇒ reason `"cancelled"`. `test_scanner_engine_routes.py` — 202/400/404/429 status codes, a finished job's `result` equals `_build_run_response` output, `"context": null` no longer 500s on either endpoint, client `deadline`/`cancelled` dropped.

Extension: `extension/tests/job-poller.test.mjs` run with `node --test` (built into Node, no dependency): progressive delivery without duplicates, stop on done/cancelled/error, timeout ⇒ cancel then partial result, consecutive-error give-up. `npm test` script in `extension/package.json` runs it. `node --check` on edited files.

## Out of scope

Resuming a scan in a new service-worker instance (the job id is stored, but reattaching `currentScan` after a worker restart is a later round); streaming findings before the run's bayesian merge (findings stay final-only so dedup/inference/triage are unchanged); a cancel button separate from Stop.
