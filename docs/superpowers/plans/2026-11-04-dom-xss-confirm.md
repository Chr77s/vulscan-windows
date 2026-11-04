# DOM XSS Confirmation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Confirm DOM-based XSS by loading probe URLs in a hidden browser tab and observing a payload-set marker attribute, producing a high-confidence finding.

**Architecture:** A pure ES module builds probes, runs them through an injected `check()` and maps hits to findings (Node-tested). The service worker supplies `check()` with one minimized window/tab and `chrome.scripting.executeScript`, gated by profile and a new config key.

**Tech Stack:** Chrome MV3 (ES-module service worker, `chrome.windows`, `chrome.tabs`, `chrome.scripting`); Node 24 `node --test`.

**Spec:** `docs/superpowers/specs/2026-11-04-dom-xss-confirm-design.md`

## Global Constraints

- Payload templates, order, marker attribute `data-vulnscan-hit`, finding fields and copy: exactly as in the spec's Design section.
- `maxProbes = 16`, `budgetMs = 40000`, page-complete cap `4000` ms, `settleMs = 600`; the hash pseudo-parameter is named `#hash`.
- Runs only if `cfg.activeEnabled` AND `cfg.scanProfile` ∈ {`deep`, `owasp`, `custom`} AND `cfg.domXssConfirm !== false`; `DEFAULT_CONFIG.domXssConfirm = true`.
- Probe URLs stay on the scanned URL's origin (only one parameter value changes).
- One window, one tab, reused; closed in `finally`. Nothing runs in the page's MAIN world.
- `npm test` in `extension/` stays green (16 today); `node --check` on every edited JS file. Host has 3.5 GB RAM: one command at a time.

## Review Focus

1. A parameter whose value contains characters that need encoding (`&`, `#`, `+`, spaces) — probe URLs must round-trip through `URL`/`URLSearchParams` so other parameters keep their original values (Task 1 test).
2. A page with no query and no hash still gets the `#hash` probes, and a URL that already has a fragment has it replaced, not appended (Task 1 test).
3. A `check()` that hangs must be bounded by the runner's budget (`now()` advanced past `budgetMs` ⇒ stop) — Task 1 test with a fake clock.
4. Stop pressed during the DOM phase: no finding is written to a stopped/replaced scan and the probe window is closed — Task 2 trace.
5. The probe tab must not steal focus or appear as a new tab in the user's window (minimized separate window) — Task 2 trace + controller browser check.

---

### Task 1: Pure probe module + node tests

**Files:** Create `extension/src/utils/dom-xss-probe.js`, `extension/tests/dom-xss-probe.test.mjs`.

**Interfaces — Produces:** `export const DOM_PAYLOAD_TEMPLATES` (array of `{ context, template }`, contexts `html`, `js-single`, `js-double`, `js-url`); `export function buildDomProbes(url, { maxProbes = 16, makeToken }) -> Array<{ param, context, token, payload, probeUrl }>`; `export async function runDomProbes({ probes, check, now, budgetMs = 40000, isStopped = () => false }) -> Array<probe>` (hits); `export function domFindingFromHit(hit) -> object` with the spec's finding fields.

- [ ] **Step 1: Failing tests** (`node:test`, fake token generator, fake clock): `builds one probe per param per template in order`, `adds #hash probes and replaces an existing fragment`, `keeps other params intact and round-trips encoded values`, `caps at maxProbes`, `tokens are unique and appear in payload`, `runner stops a parameter after its first hit`, `runner stops at budget`, `runner stops when isStopped`, `throwing check counts as not confirmed`, `finding has the spec fields and copy`.
- [ ] **Step 2: Run** `npm test` in extension/ — new tests FAIL.
- [ ] **Step 3: Implement** with `URL` / `URLSearchParams` only; no `chrome.*`, no globals.
- [ ] **Step 4: Run** `npm test` — all PASS; `node --check` the module.
- [ ] **Step 5: Commit** `feat(extension): pure DOM XSS probe builder and runner`

### Task 2: Service worker phase + options toggle

**Files:** Modify `extension/src/background/service-worker.js`, `extension/src/utils/constants.js` (`DEFAULT_CONFIG.domXssConfirm = true`), `extension/src/options/options.html` + `options.js` (one checkbox, following the existing checkbox pattern and its save logic that must not wipe other fields).

**Interfaces — Consumes:** Task 1 exports.

- [ ] **Step 1: Implement** `checkProbeInTab(tabId, probe)` (tabs.update → wait `complete` via tabs.onUpdated with the 4000 ms cap → `settleMs` → `scripting.executeScript({ target: { tabId }, func: () => document.documentElement.getAttribute("data-vulnscan-hit") })` → compare to `probe.token`); the DOM phase after the active phase in `startScan`, gated per Global Constraints, using one minimized window created once and removed in `finally`, `runDomProbes` with `isStopped` bound to the scan's `stopped()` guard, hits mapped through `domFindingFromHit` → `ensureFinding` → pushed and broadcast exactly like other findings (only while not stopped); one module-log entry `{ module: "dom-xss", findings: n, elapsedMs }`, or an error entry if the window cannot be created.
- [ ] **Step 2: Verify** `node --check` on all edited JS; `npm test` green; trace in the report: (a) profile standard ⇒ phase skipped; (b) deep + activeEnabled ⇒ window created minimized, probes run, window closed; (c) Stop mid-phase ⇒ no write, window closed; (d) `domXssConfirm` unchecked in options ⇒ skipped, and saving options keeps every other field.
- [ ] **Step 3: Commit** `feat(extension): confirm DOM XSS in a hidden tab during deep scans`
