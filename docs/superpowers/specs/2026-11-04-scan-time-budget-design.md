# Scan time budget — partial results instead of silent total loss

Date: 2026-11-04. Status: approved (user granted autonomous decisions for this improvement round).

## Problem (verified in code)

- `ScannerEngine.run()` (`backend/scanner/core/engine.py`) runs the crawler (up to 30 pages) then every enabled module **sequentially**, with no notion of elapsed time. Each module issues many requests with 8 s timeouts.
- The extension calls `POST /scanner/run` with `AbortSignal.timeout(60000)` (`extension/src/background/service-worker.js`, `runActiveModules`). On abort, the `catch` returns `{ findings: [] }`.
- So when a scan exceeds 60 s — likely for the Deep/OWASP profiles on any real site — **every active finding from every module is lost**, and the user sees only a `console.warn`. The modules that finished in time are discarded along with the one that was slow.

## Goal

A scan always returns what it found within its time budget, and says which modules it did not get to. No finding that a module produced in time is ever lost to a timeout.

## Design

### Backend: one deadline, enforced at three points

`context["time_budget_s"]` (number, optional) is the scan's budget. When present, `engine.run()` sets `context["deadline"] = time.monotonic() + time_budget_s` once, at the start (unless the caller already set `deadline`). Absent budget ⇒ no deadline ⇒ behavior identical to today (every existing test keeps passing unchanged).

1. **`http.send()`** (`backend/scanner/core/http.py`) — the single path almost every module uses:
   - If `context["deadline"]` exists and is already past, return without sending (`None`, or `(None, None, None)` when `capture=True`). Modules already treat `None` as "no response, continue", so their loops drain quickly.
   - Otherwise clip the request's `timeout` (after `_merged_kwargs` has applied `DEFAULT_TIMEOUT`, so a call without an explicit timeout is clipped too) to the remaining time: `max(0.5, min(timeout, remaining))` — never above the caller's own value, and a 0.5 s floor so a request is never sent with a zero/negative timeout. A `(connect, read)` tuple timeout gets each element clipped the same way.
2. **Engine, between modules** — before instantiating each module, if the deadline is past, do not run it; append to the module log `{"module": name, "findings": 0, "elapsed_ms": 0, "status": "skipped", "reason": "time_budget"}`. Findings from modules that ran are kept, merged and passed through inference exactly as today.
3. **Crawler** — `Crawler` accepts an optional `deadline` (monotonic timestamp); the engine passes `context.get("deadline")`. The crawler stops visiting new pages (and skips robots/sitemap fetches) once past it, returning what it discovered so far.

Paths that bypass `http.send` (`ssl_tls` sockets, `subdomain_enum` DNS/crt.sh, `oob` polling) are bounded only by the between-module check: a module that starts just before the deadline can overrun by its own internal maximum (~15 s). This is why the extension's abort is set 15 s above the budget. Mark this with a `shortcut:` comment in the engine.

Each module declares `min_time_to_start_s` (default 0; `ssl_tls` 30 s, `subdomain_enum` 25 s): when a deadline exists, the engine skips a module whose worst-case duration outside `http.send` exceeds the time left, with the same `skipped` log entry.

### API

`routes/scanner_engine.py::_module_log_entry` exposes `status: "skipped"` and `reason` the same way it already exposes `status: "error"`. No other response field changes.

### Extension

- `service-worker.js`: a `TIME_BUDGET_FOR_PROFILE` map next to `DEPTH_FOR_PROFILE` — `quick`/`standard`: 45 s; `deep`/`owasp`/`api`/`custom`: 150 s; unknown profile: 45 s. Send `context.time_budget_s`; set the fetch abort to `(budget + 15) * 1000` ms. Chrome's documented termination conditions for an extension service worker include "When a fetch() response takes more than 30 seconds to arrive" (developer.chrome.com, service-worker lifecycle, read 2026-11-04); the page does not say whether this covers fetches the worker itself makes. If it does, any `/scanner/run` call slower than 30 s is at risk with or without this branch (it already was at 60 s). Resolution is out of scope here: an asynchronous job API (start with POST, poll with short GETs) is the planned follow-up.
- `panel.js::formatModuleLogLine`: a skipped entry renders as `⏱ <module> — non exécuté (budget temps atteint)`. When at least one entry is skipped, the activity console's first line says `Scan partiel : N module(s) non exécuté(s) faute de temps — relancez avec un profil plus ciblé.`
- Popup and exported reports: when `moduleLog` has a skipped entry, the popup and the HTML/PDF report show `Scan partiel : N module(s) non exécuté(s) faute de temps — ce rapport ne couvre pas toute la surface testée.` (SARIF/XML carry a `skippedModules` marker), so a partial scan is never handed over as clean.

## Error handling

- A budget of 0 or negative is treated as absent (no deadline), not as "skip everything".
- The deadline is advisory, never an exception: nothing raises because time ran out.

## Testing

Backend (pytest, TDD):
- `http.send` with a past deadline returns `None` / `(None, None, None)` and never calls `requests.request`.
- `http.send` with a future deadline clips `timeout` to the remaining time (assert the kwarg passed to `requests.request`), respects the 0.5 s floor, and never raises a caller timeout above its own value.
- `engine.run` with a budget that expires during module 1 (fake module that advances a patched clock): module 1's findings are returned; modules 2..n are in the log with `status == "skipped"`, `reason == "time_budget"`.
- `engine.run` without `time_budget_s`: no `deadline` key added, nothing skipped.
- `Crawler` with a past deadline visits no page beyond what it already had; with no deadline, behavior unchanged.
- Route: a skipped engine log entry is exposed with `status` and `reason`.

Extension: `node --check` on both edited files; browser verification of the console rendering with a stubbed `moduleLog`.

## Out of scope

Parallel module execution (would change rate-limiting semantics and evidence ordering), per-module budgets, a UI control to edit the budget.
