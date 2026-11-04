# Scan Time Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A scan returns every finding produced within its time budget and names the modules it did not reach, instead of losing all active findings when the extension's request times out.

**Architecture:** One monotonic deadline in the scan `context`, set by the engine from `context["time_budget_s"]`, enforced in `http.send()` (refuse/clip), between modules in `ScannerEngine.run()` (skip + log), and in the crawler (stop visiting). The extension sends a per-profile budget and aborts 15 s after it; the panel renders skipped modules.

**Tech Stack:** Python 3 / Flask / requests / pytest + pytest-mock (backend); Chrome MV3 vanilla JS (extension, no JS test runner).

**Spec:** `docs/superpowers/specs/2026-11-04-scan-time-budget-design.md`

## Global Constraints

- No `time_budget_s` in context ⇒ no `deadline` key is added and behavior is byte-for-byte today's (every existing test passes unchanged — 155 on this branch's base).
- A budget that is ≤ 0, or not a number (e.g. `"abc"`), is treated as absent. A numeric string (`"45"`) is accepted (JSON callers).
- Timeout clip formula: `max(0.5, min(timeout, remaining))`; tuple timeouts clip each element.
- Skipped module log entry, exactly: `{"module": name, "findings": 0, "elapsed_ms": 0, "status": "skipped", "reason": "time_budget"}`.
- Extension budgets: `quick` 45, `standard` 45, `deep` 150, `owasp` 150, `api` 150, `custom` 150, unknown 45 (seconds); fetch abort = `(budget + 15) * 1000` ms.
- Panel copy, exactly: skipped line `⏱ <module> — non exécuté (budget temps atteint)`; banner line `Scan partiel : N module(s) non exécuté(s) faute de temps — relancez avec un profil plus ciblé.`
- Nothing raises because time ran out. Python run from the worktree root with `C:\vulnscan-windows\backend\.venv\Scripts\python.exe -m pytest backend/tests/ -q`.

## Review Focus

1. Deadline already past when `send()` is called: it must not sleep in `_throttle` first (the check comes before throttling) — test in Task 1.
2. Budget delivered as a JSON string or garbage — Task 2 test with `"45"` (accepted) and `"abc"` (ignored, no crash).
3. A caller-supplied `deadline` in context must not be overwritten by the engine — Task 2 test.
4. A module that crashes after the deadline is still logged as `error`, and later modules are still logged as `skipped` — Task 2 test.
5. A history-restored scan (`currentScan.moduleLog` from storage) containing skipped entries renders the skipped line and banner, not `✓ … 0 findings` — Task 3 browser check.

---

### Task 1: Deadline in `http.send()`

**Files:**
- Modify: `backend/scanner/core/http.py` (`send()` and a new helper above it)
- Test: `backend/tests/test_http_client.py`

**Interfaces:**
- Produces: `time_left(context: Optional[Dict[str, Any]]) -> Optional[float]` in `scanner.core.http` — `None` when `context` has no `deadline`, else `deadline - time.monotonic()` (may be ≤ 0). Task 2 imports it.

- [ ] **Step 1: Write the failing tests** in `backend/tests/test_http_client.py`:
  - `test_send_with_past_deadline_sends_nothing` — `context={"deadline": time.monotonic() - 1}`; patch `scanner.core.http.requests.request` and `scanner.core.http._throttle`; `http.get("http://a/", context) is None`; `http.get("http://a/", context, capture=True) == (None, None, None)`; neither patch was called.
  - `test_send_clips_timeout_to_remaining_time` — `deadline = monotonic() + 2`; call `http.get(url, ctx, timeout=8)`; assert the `timeout` kwarg passed to `requests.request` is `<= 2` and `>= 0.5`.
  - `test_send_never_raises_callers_timeout` — `deadline = monotonic() + 100`, `timeout=3` ⇒ kwarg `== 3`.
  - `test_send_timeout_floor_is_half_second` — `deadline = monotonic() + 0.1` ⇒ kwarg `== 0.5`.
  - `test_send_clips_tuple_timeout` — `deadline = monotonic() + 2`, `timeout=(5, 8)` ⇒ both elements `<= 2` and `>= 0.5`.
  - `test_send_without_deadline_is_unchanged` — `context={}` and `timeout=8` ⇒ kwarg `== 8`.
  - `test_time_left` — `time_left(None) is None`; `time_left({}) is None`; `time_left({"deadline": monotonic() + 5})` is between 4 and 5.
- [ ] **Step 2: Run** `... -m pytest backend/tests/test_http_client.py -v` — the new tests FAIL (no `time_left`, no clipping).
- [ ] **Step 3: Implement** `time_left()` and, in `send()`, before `_throttle`: if `time_left(context)` is not `None` and `<= 0`, return `(None, None, None)` if `capture` else `None`. After `_merged_kwargs`, when a deadline exists, clip `opts["timeout"]` with the Global Constraints formula (tuple-aware).
- [ ] **Step 4: Run** the file, then the full suite — all PASS.
- [ ] **Step 5: Commit** `feat(http): honor a scan deadline — refuse after it, clip timeouts before it`

### Task 2: Engine budget, crawler stop, route exposure

**Files:**
- Modify: `backend/scanner/core/engine.py` (`ScannerEngine.run`), `backend/scanner/core/crawler.py` (`Crawler.__init__`, `crawl`), `backend/routes/scanner_engine.py` (`_module_log_entry`)
- Test: `backend/tests/test_engine.py`, `backend/tests/test_crawler.py`, `backend/tests/test_scanner_engine_routes.py`

**Interfaces:**
- Consumes: `time_left(context)` from Task 1.
- Produces: `Crawler(max_depth=1, max_pages=30, timeout=5, user_agent=..., deadline: Optional[float] = None)`; engine skipped-entry shape (Global Constraints); `_module_log_entry` returns `status`/`reason` for skipped entries.

- [ ] **Step 1: Write the failing tests.**
  `backend/tests/test_engine.py` (register fake `ScannerModule` subclasses on a fresh `ScannerEngine()`, `crawl=False`, follow the file's existing fake-module style):
  - `test_budget_skips_modules_after_deadline` — module A returns one finding and sets `context["deadline"] = time.monotonic() - 1` inside its `scan`; modules B, C would return findings. Run with `context={"time_budget_s": 30}`, `enabled=["a","b","c"]`. Assert A's finding is in the result; B and C are absent; the module log (whichever of `context["module_log"]` / `engine.last_module_log` the file already asserts on) has B and C with `status == "skipped"`, `reason == "time_budget"`, `findings == 0`, `elapsed_ms == 0`.
  - `test_no_budget_adds_no_deadline` — `context={}` ⇒ after `run`, `"deadline" not in context`, nothing skipped.
  - `test_budget_string_and_garbage` — `{"time_budget_s": "45"}` ⇒ `"deadline" in context`; `{"time_budget_s": "abc"}` and `{"time_budget_s": 0}` ⇒ `"deadline" not in context`, no exception.
  - `test_existing_deadline_not_overwritten` — `context={"time_budget_s": 30, "deadline": 123.0}` ⇒ `context["deadline"] == 123.0` after `run` (and every module is skipped, since 123.0 is in the past).
  - `test_crash_after_deadline_still_logged_as_error` — module A sets a past deadline then raises; B is skipped. A's entry has `status == "error"`, B's `status == "skipped"`.
  `backend/tests/test_crawler.py`:
  - `test_crawler_with_past_deadline_fetches_nothing` — `Crawler(deadline=time.monotonic() - 1)`; patch `scanner.core.crawler.requests.get`; `crawl("http://a/")` returns a result whose `urls` holds at most the seed, and `requests.get` was never called.
  - `test_crawler_without_deadline_unchanged` — existing behavior with a mocked page still visits it (reuse the file's existing mocking pattern).
  `backend/tests/test_scanner_engine_routes.py`:
  - `test_module_log_entry_exposes_skipped` — `_module_log_entry({"module":"x","findings":0,"elapsed_ms":0,"status":"skipped","reason":"time_budget"})` ⇒ `{"module":"x","findings":0,"elapsedMs":0,"status":"skipped","reason":"time_budget"}`.
- [ ] **Step 2: Run** the three files — new tests FAIL.
- [ ] **Step 3: Implement.** Engine: at the top of `run`, parse `time_budget_s` (accept int/float/numeric string, > 0) and `context.setdefault("deadline", time.monotonic() + budget)`; pass `deadline=context.get("deadline")` to `Crawler`; in the module loop, before `cls()`, if `time_left(context)` is not `None` and `<= 0`, append the skipped entry and `continue`. Add one comment: `# shortcut: ssl_tls/subdomain_enum/oob bypass http.send, so a module started just before the deadline can overrun by its own max (~15 s); the extension aborts 15 s after the budget for that reason — upgrade to per-module cancellation if that margin proves too small.` Crawler: store `deadline`; in the `while` loop condition and before `_fetch_robots_sitemap`, stop once `time.monotonic() >= deadline`. Route: extend the existing `if e.get("status") == "error"` branch to also expose `status` and `reason` when `status == "skipped"`.
- [ ] **Step 4: Run** the three files, then the full suite — all PASS.
- [ ] **Step 5: Commit** `feat(engine): enforce a scan time budget — skip late modules, stop crawling, report partial`

### Task 3: Extension — per-profile budget and partial-scan rendering

**Files:**
- Modify: `extension/src/background/service-worker.js` (next to `DEPTH_FOR_PROFILE`; `runActiveModules`), `extension/src/devtools/panel.js` (`formatModuleLogLine` and the console render that builds `moduleLogLines`)

**Interfaces:**
- Consumes: skipped entries in `moduleLog` as `{module, findings, elapsedMs, status: "skipped", reason: "time_budget"}` (Task 2).

- [ ] **Step 1: service-worker.js** — add `TIME_BUDGET_FOR_PROFILE` with the Global Constraints values; in `runActiveModules`, `const budget = TIME_BUDGET_FOR_PROFILE[cfg.scanProfile] || 45;`, send `time_budget_s: budget` in `context`, and use `AbortSignal.timeout((budget + 15) * 1000)` with the existing comment updated.
- [ ] **Step 2: panel.js** — `formatModuleLogLine` returns the skipped copy for `e.status === "skipped"`; wherever the console lines are rebuilt from a full `moduleLog` array (the history-restore path that does `entries.map(formatModuleLogLine)`) and in the live path, prepend the banner line when ≥ 1 entry is skipped (count N = skipped entries), exactly once.
- [ ] **Step 3: Verify** `node --check extension/src/background/service-worker.js` and `node --check extension/src/devtools/panel.js` both exit 0. Then extract `formatModuleLogLine` and the banner logic's inputs into a throwaway Node script (not committed) that feeds `[{module:"a",findings:2,elapsedMs:10},{module:"b",findings:0,elapsedMs:0,status:"skipped",reason:"time_budget"}]` and prints the produced lines; confirm they match the Global Constraints copy character for character.
- [ ] **Step 4: Commit** `feat(extension): send a per-profile scan budget, show partial scans`
