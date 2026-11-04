# DOM XSS confirmation — observe the payload execute in a real browser

Date: 2026-11-04. Status: approved (user: "continue" on the ranked list; item 3).

## Problem

DOM-based XSS (a URL parameter or the hash flowing into `innerHTML`, `document.write`, `eval`, `location`) is never confirmed today. The backend scanner only sees the server's HTML, and the content script only flags dangerous sinks statically (`analyzeDomSinks`). The bundled test-site is exactly this case: `search.html?q=`, `comments.html?c=`/`?theme=`, `login.html?msg=` are all client-side sinks that no active test proves.

## Spike (done, throwaway, 2026-11-04)

In a real Chromium page served from the test-site: `search.html?q=<img src=x onerror="document.documentElement.setAttribute('data-vulnscan-hit','T1')">` set the attribute (innerHTML sink); `comments.html?theme=red}</style><img … 'T2'>` set it (document.write into `<style>`); `search.html?q=hello` left it `null`. DOM attributes are shared between the page's world and an extension's isolated world, so the extension can read the proof without injecting anything into the page's JS world and without any visible effect (no alert).

## Design

**Probe = one URL** with exactly one parameter replaced by a payload carrying a fresh random token. The payload's only effect is `document.documentElement.setAttribute('data-vulnscan-hit', TOKEN)`. Confirmed iff, after the probe page settles, that attribute equals the token. Non-destructive by construction; no alert/confirm/prompt; nothing leaves the page.

**Payload templates** (exact, `{T}` = token):
- `html`: `'"--></style></script><img src=x onerror="document.documentElement.setAttribute('data-vulnscan-hit','{T}')">` (breaks out of attribute quotes, comment, style and script contexts before injecting an element)
- `js-single`: `';document.documentElement.setAttribute('data-vulnscan-hit','{T}');//`
- `js-double`: `";document.documentElement.setAttribute('data-vulnscan-hit','{T}');//`
- `js-url`: `javascript:document.documentElement.setAttribute('data-vulnscan-hit','{T}')`

**Where:** every query parameter of the scanned URL, plus the fragment (`#` + payload) as a pseudo-parameter named `#hash`. Probes ordered parameter by parameter, templates in the order above; once a parameter is confirmed, its remaining templates are skipped. At most `maxProbes = 16` probes, and the whole phase stops at `budgetMs = 40000` or when the scan is stopped.

**Execution:** one minimized browser window with one tab, reused for every probe (`chrome.windows.create({ state: "minimized" })`, then `chrome.tabs.update(tabId, { url })`). Per probe: wait for `status === "complete"` (cap 4000 ms), wait `settleMs = 600` for async sinks, read the attribute with `chrome.scripting.executeScript` (isolated world). The window is always closed in a `finally`. Same origin as the scanned URL only (the probe URL is the scanned URL with one value changed). Runs only when `cfg.activeEnabled` is true AND the profile is `deep`, `owasp` or `custom`, AND `cfg.domXssConfirm !== false` (new config key, default `true`).

**Finding** (through the existing `ensureFinding` path): `type: "xss"`, `title: "DOM XSS confirmée — exécution observée"`, `severity: "high"`, `confidence: 95`, `detectionMethod: "dom-execution-confirmed"`, `source: "extension:dom-xss"`, `parameter` (name or `#hash`), `payload`, `url` (the probe URL), `evidence: "Le payload a posé data-vulnscan-hit=<token> sur <html> (contexte <template>)"`, `cwe: "CWE-79"`, `owasp: "A03:2021"`.

**Units:**
- `extension/src/utils/dom-xss-probe.js` (pure, Node-testable): `buildDomProbes(url, { maxProbes, makeToken }) -> Probe[]`, `runDomProbes({ probes, check, now, budgetMs, isStopped }) -> Promise<Hit[]>` (sequential; `check(probe) -> Promise<boolean>`; skips a parameter's remaining templates after a hit; stops on budget/stop; a throwing `check` counts as "not confirmed" and never aborts the run), `domFindingFromHit(hit) -> object`, `DOM_PAYLOAD_TEMPLATES`.
- Service worker: `checkProbeInTab(tabId, probe)` (navigate, wait complete with cap, settle, read attribute) and the phase wiring after the active phase, writing nothing once the scan is stopped/replaced (reuse `stopped()` / the run guards).
- Options page: one checkbox for `domXssConfirm`.

## Error handling

A probe that times out, errors, or whose tab navigates away counts as not confirmed. Failure to create the window skips the phase with one activity-console line (`{ module: "dom-xss", status: "error", error }`). The phase's own module-log entry reports probes run and hits: `{ module: "dom-xss", findings: <n>, elapsedMs }`.

## Testing

`node --test`: probe building (params + hash, templates, maxProbes, token uniqueness, URL encoding round-trip), runner (skip-after-hit, budget stop, isStopped stop, throwing check), finding mapping. Real-browser check by the controller in the browser pane against the served test-site: each template's payload URL on search/comments/login sets the attribute where a sink exists, and a clean value does not.

## Out of scope

Stored XSS, POST-driven DOM XSS, postMessage/DOM-clobbering sources, cross-origin targets.
