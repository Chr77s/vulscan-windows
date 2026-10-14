# Round 8 — Reports Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring VulnScan's export/report surface up to the same bar as its detection engine (Round 6) and UI (Round 7) — exports actually contain the evidence and triage decisions users already have in the panel, a SARIF artifact for CI/GitHub Code Scanning, a data-driven executive summary instead of fixed prose, remediation guidance on the highest-volume finding types, and a risk-trend sparkline per target.

**Architecture:** Every export format (`buildCSV`/`buildXML`/`buildHTMLReport`, plus the new `buildSARIF`) is a pure client-side function in `extension/src/devtools/panel.js`, dispatched from the single `exportReport(format)` entry point — this round follows that exact existing pattern for SARIF too, adds one shared pre-filter (false positives) ahead of all of them, and adds one new backend-only capability (`risk_trend`) that the panel fetches directly, mirroring how Round 7's Modules tab already reads `GET /scanner/modules` straight from the panel's own context for a safe, side-effect-free read.

**Tech Stack:** Vanilla JS (ES modules) in the extension, Flask + SQLite on the backend (one new query, one new route). No new dependency for either side — SARIF is hand-built JSON (no `@microsoft/sarif-sdk` or similar), the trend sparkline is an inline SVG polyline (same no-charting-library philosophy as the existing donut), PDF stays browser-print (`window.print()`), unchanged.

**Spec:** [docs/superpowers/specs/2026-10-14-vulnscan-premium-hardening-design.md](../specs/2026-10-14-vulnscan-premium-hardening-design.md) §4 (Round 8).

## Global Constraints

- No framework (React/Vue) and no test framework for the extension (spec §1 non-objectifs, reaffirmed every round) — verification there is `node --check` plus hand-tracing against the real SARIF 2.1.0 shape, not a pytest file. (The spec's §4.8 mentions `test_sarif.py`; grounding against the actual codebase shows `buildSARIF` is client-side JS like every other export format, so this plan treats that mention as imprecise and follows the established extension-verification convention instead — a ruling, not a silent contradiction. `test_risk_trend.py` IS a real backend pytest file, since `risk_trend()` is Python.)
- PDF export stays browser-print-based — no new rendering dependency (spec §4.7, unchanged from today).
- Every export format is a client-side function dispatched from `exportReport(format)` in `panel.js` — this round does not introduce a backend report-generation route for any format. The one new backend capability (`risk_trend`) is a data query, not a report.
- The false-positive export filter (Task 1) is a single point ahead of all format dispatch — never a per-format special case, and never bypassable except via the one explicit opt-in control.
- `evidenceRequest`/`evidenceResponse` fields exported anywhere (Task 2) are the fields already present on the finding object, already redacted per Round 6's auth-header-redaction rules (`http.py`'s capture-time redaction) — exporting never re-captures or re-derives evidence, and never un-redacts it.
- Severity hues (`--critical`/`--high`/`--medium`/`--low`/`--info`) and the `--sev-text-*` text-safe variants (Round 7) stay as the only source of severity color in anything rendered in the live panel — this round's new live-panel UI (the export checkbox, the SARIF button, the Historique sparkline) must not hardcode a severity color outside that system. The exported HTML report's own separate, always-light, static `<style>` block (`buildHTMLReport`) is explicitly exempt, as established in Round 7 — it is not theme-reactive and never has been.

## Review Focus

- **A false-positive finding escaping the export filter through one format but not another.** The filter in Task 1 must be a single point ahead of the per-format dispatch in `exportReport()`, applied identically to CSV/XML/HTML/PDF/SARIF — Task 1's own test must cover more than one format, not just the one a careless implementation might filter.
- **Exported evidence silently bypassing Round 6's auth-header redaction.** A finding whose `evidenceRequest.headers` already has a configured auth header redacted (e.g. `Authorization: [REDACTED]`) must still show it redacted in the exported XML/HTML — Task 2 must verify this against a finding that actually has a redacted header, not just an evidence-free finding.
- **A SARIF result with an empty/missing required field getting silently accepted by `buildSARIF` and rejected downstream by GitHub Code Scanning.** A finding with no `url` (some informational/passive types lack one) or no `description` must still produce a valid non-empty string in `locations[].physicalLocation.artifactLocation.uri` and `message.text` — Task 3 must test this exact edge case, not just the common case where every field is populated.
- **The trend sparkline crashing on a target's first-ever scan.** `risk_trend(url, limit=10)` returning zero or one row (no prior history for this URL) must render an empty/neutral sparkline state in both the Historique tab and the exported HTML report's header, never throw — Task 6 must test the zero-row and one-row cases explicitly, not just the "plenty of history" case.
- **A remediation snippet rendered as live HTML instead of displayed as code.** `v.remediationSnippet` is example source code (e.g. a parameterized-query snippet), never markup to execute — Task 5 must route it through `escapeHtml()` inside a `<pre>`/`<code>` block in every place it's rendered (card, HTML export, SARIF `fixes[].description.text`), exactly like `v.payload`/`v.evidence` already are, and must verify this with a snippet containing `<`/`>`/`&`.

---

## Task 1: Exclude false positives from exports

**Why this task exists:** verified directly in the merged code (not assumed): `exportReport(format)` in `panel.js` builds `scan.vulnerabilities` directly from `allVulns` with no filtering at all, so a finding a user has explicitly marked "Faux positif" (Round 7 §3.4) is exported in every format today — exactly the gap spec §3.4 called for and Round 7's own final review caught as a planning omission (not a regression), now caught up here since export behavior is this round's domain.

**Files:**
- Modify: `extension/src/utils/constants.js` (`DEFAULT_CONFIG`)
- Modify: `extension/src/devtools/panel.html` (`.export-group`)
- Modify: `extension/src/devtools/panel.js` (`exportReport`, `setupEventListeners`, panel init)

**Interfaces:**
- Modifies: `DEFAULT_CONFIG` gains `includeFalsePositivesInExport: false`.
- Produces: a checkbox `#chkIncludeFP` in `.export-group`, read once per export inside `exportReport(format)` to decide whether `allVulns` is filtered before any format-specific builder runs. Every later task in this plan (2, 3, 4, 5, 6) that touches `exportReport()` or a format builder must operate on the already-filtered list this task produces, not on `allVulns` directly.

- [ ] **Step 1: Add the config field**

In `constants.js`'s `DEFAULT_CONFIG`, add `includeFalsePositivesInExport: false,` near `customModules`.

- [ ] **Step 2: Add the checkbox**

In `panel.html`'s `.export-group` (before the existing `#btnExportJson` button), add:
```html
<label style="display:flex;align-items:center;gap:5px;font-size:11px;color:var(--text-2);margin-right:6px;white-space:nowrap">
  <input type="checkbox" id="chkIncludeFP" style="accent-color:var(--accent);cursor:pointer">
  Inclure les faux positifs
</label>
```

- [ ] **Step 3: Wire persistence**

On panel init (wherever `GET_CONFIG` is already read during startup — find the existing init sequence and add to it, don't create a second one), set `document.getElementById("chkIncludeFP").checked = !!cfg.includeFalsePositivesInExport`. Add a `change` listener in `setupEventListeners()`:
```javascript
document.getElementById("chkIncludeFP").addEventListener("change", async (e) => {
  const result = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
  if (!result || result.error) { console.warn("[VulnScan] GET_CONFIG KO, réglage non sauvegardé"); return; }
  await chrome.runtime.sendMessage({
    type: "SET_CONFIG",
    payload: { ...result, includeFalsePositivesInExport: e.target.checked },
  });
});
```
(Matches the `GET_CONFIG`-error-guard pattern already established for `onToggleTheme`/`onModuleCheckboxChange` — never spread a `{error}` reply into `SET_CONFIG`.)

- [ ] **Step 4: Filter in `exportReport`**

At the top of `exportReport(format)`, right after the `allVulns.length === 0` guard, add:
```javascript
const includeFP = document.getElementById("chkIncludeFP")?.checked ?? false;
const vulnsToExport = includeFP ? allVulns : allVulns.filter(v => v.triageStatus !== "false_positive");
```
Change the `scan` object literal's `vulnerabilities: allVulns` to `vulnerabilities: vulnsToExport`. This is the ONLY filter point — every format dispatched below it (`json`/`csv`/`html`/`xml`/`pdf`, and `sarif` once Task 3 lands) already reads from `scan.vulnerabilities`, so none of them need their own filter.

- [ ] **Step 5: Verify**

Run: `node --check extension/src/devtools/panel.js extension/src/utils/constants.js` (`panel.html` is also modified but isn't JS and has no syntax checker — review it by eye).
Expected: no output.

Hand-trace (Review Focus #1): build a fake `allVulns` with 2 findings, one `triageStatus: "false_positive"`. With the checkbox unchecked, confirm `vulnsToExport` has 1 entry for EVERY format branch (`json`/`csv`/`html`/`xml`/`pdf` — they all read the same `scan.vulnerabilities`, so tracing one confirms all). With it checked, confirm both entries survive.

- [ ] **Step 6: Commit**

```bash
git add extension/src/utils/constants.js extension/src/devtools/panel.html extension/src/devtools/panel.js
git commit -m "feat(extension): exclude false positives from exports by default (spec §3.4 catch-up)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Request/response evidence in XML and HTML exports

**Why this task exists:** verified directly in the merged code: `buildXML`/`buildHTMLReport` already export the old free-text `v.evidence` string, but never the Round 6 `evidenceRequest`/`evidenceResponse` objects that the Traffic tab (Round 7) already renders — the JSON export already has them "for free" (it's the same object, no change needed there).

**Files:**
- Modify: `extension/src/devtools/panel.js` (`buildXML`, `buildHTMLReport`)

**Interfaces:**
- Consumes: `v.evidenceRequest`/`v.evidenceResponse` (same shape as the Traffic tab already consumes: `{method, url, headers, body}` / `{status, headers, body_snippet, elapsed_ms}`), and Task 1's `vulnsToExport`/`scan.vulnerabilities` (already filtered — this task does not add its own filter).

- [ ] **Step 1: XML — add the two new tags**

In `buildXML`'s per-finding loop, after the existing `if (v.evidence) xml += ...` line, add:
```javascript
if (v.evidenceRequest) {
  xml += `      <evidence-request><![CDATA[${JSON.stringify(v.evidenceRequest)}]]></evidence-request>\n`;
}
if (v.evidenceResponse) {
  xml += `      <evidence-response><![CDATA[${JSON.stringify(v.evidenceResponse)}]]></evidence-response>\n`;
}
```
(CDATA handles any character in the JSON — headers, bodies — without needing `esc()`; this matches the existing `<payload>`/`<evidence>` tags' own CDATA pattern in the same function.)

- [ ] **Step 2: HTML — add a collapsible detail block in the existing evidence cell**

In `buildHTMLReport`'s row template, change the `<pre>${escapeHtml((v.evidence || "").slice(0, 300))}</pre>` cell to also include a `<details>` block when request/response evidence exists (keeps the existing 12-column table width unchanged — a 13th raw column would make an already-wide table impractical to read or print, so this follows the spec's own word "dépliable" literally):
```javascript
<td><pre>${escapeHtml((v.evidence || "").slice(0, 300))}</pre>${
  v.evidenceRequest || v.evidenceResponse
    ? `<details><summary style="cursor:pointer;color:#4f46e5;font-size:10px;margin-top:4px">Requête / Réponse capturée</summary><pre style="margin-top:4px">${escapeHtml(JSON.stringify({ request: v.evidenceRequest, response: v.evidenceResponse }, null, 2).slice(0, 2000))}</pre></details>`
    : ""
}</td>
```

- [ ] **Step 3: Verify**

Run: `node --check extension/src/devtools/panel.js`
Expected: no output.

Hand-trace (Review Focus #2): construct a finding with `evidenceRequest.headers` containing `Authorization: "[REDACTED]"` (the shape `http.py`'s capture-time redaction already produces — confirm by reading `backend/scanner/core/http.py`'s redaction logic, don't assume the literal string). Confirm the exported XML's `<evidence-request>` CDATA and the HTML's `<details>` block both show `[REDACTED]` verbatim, not the real header value — since this task only serializes the finding object as given, it cannot un-redact anything, but verify there is no second, unredacted copy of the header reachable anywhere else on the finding object that this task might accidentally serialize instead.

- [ ] **Step 4: Commit**

```bash
git add extension/src/devtools/panel.js
git commit -m "feat(extension): include evidenceRequest/evidenceResponse in XML and HTML exports

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: SARIF 2.1.0 export

**Why this task exists:** per spec §4.3 — SARIF is the format GitHub Code Scanning and most CI pipelines consume, and today VulnScan has no equivalent of it despite Burp/Nuclei/Semgrep all supporting it; it's the most visible "pro artifact" gap.

**Files:**
- Modify: `extension/src/devtools/panel.js` (new `buildSARIF`, `exportReport`, `setupEventListeners`)
- Modify: `extension/src/devtools/panel.html` (new button in `.export-group`)

**Interfaces:**
- Produces: `buildSARIF(scan)` — returns a JSON string (SARIF 2.1.0 minimal document: one `run`, `results[]` mapped from `scan.vulnerabilities`). Consumed by `exportReport("sarif")`. Task 5 extends this function's `results[]` mapping to add a `fixes[]` key when a finding has a remediation snippet — read this task's exact object shape before writing Task 5, don't guess it.
- `exportReport`'s format dispatch gains an `else if (format === "sarif")` branch.

- [ ] **Step 1: Implement `buildSARIF(scan)`**

Add, near the other `build*` functions:
```javascript
function sarifLevelFor(severity) {
  return severity === "critical" || severity === "high" ? "error"
       : severity === "medium" ? "warning"
       : "note";
}

function buildSARIF(scan) {
  return JSON.stringify({
    version: "2.1.0",
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    runs: [{
      tool: {
        driver: {
          name: "VulnScan",
          informationUri: "https://github.com/",
          version: "1.2",
          rules: [],
        },
      },
      results: scan.vulnerabilities.map(v => ({
        ruleId: v.type || "unknown",
        level: sarifLevelFor(v.severity),
        message: { text: v.description || v.title || v.type || "Finding" },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: v.url || scan.url || "" },
          },
        }],
      })),
    }],
  }, null, 2);
}
```
(`rules: []` is intentionally empty — the spec's own §4.3 text only specifies `ruleId`/`level`/`message.text`/`locations[].physicalLocation.artifactLocation.uri`; populating `tool.driver.rules[]` with per-rule metadata is valid SARIF but not something this spec asks for — do not add it, YAGNI.)

- [ ] **Step 2: Wire the export dispatch and button**

In `exportReport`, add `else if (format === "sarif") { downloadBlob(buildSARIF(scan), \`${baseName}.sarif\`, "application/sarif+json"); }` alongside the existing format branches (after `vulnsToExport`/`scan` are built, same as every other format — no special-casing).

In `panel.html`'s `.export-group`, add `<button class="btn btn-secondary" id="btnExportSarif">⬇ SARIF</button>` after `#btnExportCsv`. In `setupEventListeners()`, add `document.getElementById("btnExportSarif").addEventListener("click", () => exportReport("sarif"));` alongside the other export button wiring.

- [ ] **Step 3: Verify**

Run: `node --check extension/src/devtools/panel.js`
Expected: no output.

Hand-trace (Review Focus #3): construct a finding with `url: undefined` and `description: undefined` (an informational finding type that genuinely lacks both, if one exists in the codebase — check `module_base.py`'s `Finding` dataclass defaults; `url` is actually required there with no default, so a truly empty case may not occur from a real module, but a client-sourced or malformed finding could still lack it) — confirm `buildSARIF` still produces `locations[].physicalLocation.artifactLocation.uri === ""` and `message.text` falls back to `v.title || v.type || "Finding"`, never `undefined` or `null` in the JSON output (`JSON.stringify` would otherwise either omit the key or emit the literal string `"undefined"` depending on how the fallback chain is written — confirm the actual fallback chain written in Step 1 can never produce either).

- [ ] **Step 4: Commit**

```bash
git add extension/src/devtools/panel.js extension/src/devtools/panel.html
git commit -m "feat(extension): add SARIF 2.1.0 export for CI / GitHub Code Scanning

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: Data-driven executive summary in the HTML export

**Why this task exists:** per spec §4.4 — `buildHTMLReport()`'s summary paragraph today is fixed prose with only the numbers substituted in; replacing it with text actually derived from the findings (top OWASP categories, delta vs. the last scan of the same URL) is what makes a report look analyzed rather than templated.

**Files:**
- Modify: `extension/src/devtools/panel.js` (`buildHTMLReport`, `exportReport`)

**Interfaces:**
- Consumes: `GET /history/list?url=<encoded url>&limit=2` (existing route, already supports `url_filter` — confirmed in `backend/routes/history.py`/`database/db.py`, no backend change needed for this task) to find the immediately-prior scan of the same URL, if any.
- Modifies: `buildHTMLReport(scan, forPrint, priorScan)` gains a third parameter — the caller (`exportReport`) is responsible for fetching `priorScan` before calling it, so `buildHTMLReport` itself stays a pure, synchronous string-builder (no new async work inside it, consistent with every other `build*` function in this file).

- [ ] **Step 1: Fetch the prior scan in `exportReport`**

Before calling `buildHTMLReport` (both the `"html"` and `"pdf"` branches, since both call it), add:
```javascript
async function fetchPriorScanForSummary(url, excludeId) {
  try {
    const { config } = await chrome.storage.local.get("config");
    const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };
    const r = await fetch(`${cfg.backendUrl}/history/list?url=${encodeURIComponent(url)}&limit=2`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    const data = await r.json();
    const prior = (data.scans || []).find(s => s.id !== excludeId);
    return prior || null;
  } catch (e) {
    return null;
  }
}
```
(`DEFAULT_CONFIG` here refers to `constants.js`'s shared import already used elsewhere in this file — don't redefine it.) In `exportReport`, compute `const priorScan = await fetchPriorScanForSummary(scan.url, scan.id);` once, pass it to both `buildHTMLReport(scan, false, priorScan)` and `buildHTMLReport(scan, true, priorScan)`.

**Note on sequencing:** Task 1 (already landed by this point) added the `includeFP`/`vulnsToExport` filter earlier in the same `exportReport` function. This task's new `await fetchPriorScanForSummary(...)` call is additive — it does not touch Task 1's filter logic, just adds a new async step before the `buildHTMLReport(...)` calls. Task 6 will later add a second async pre-fetch alongside this one; leave this call easy to find (don't inline it anonymously) since Task 6's brief explicitly references it by name.

- [ ] **Step 2: Compute the OWASP top-3 and the delta, build the new summary text**

In `buildHTMLReport`, replace the fixed summary paragraph with generated text:
```javascript
const owaspContribution = new Map();
for (const v of scan.vulnerabilities) {
  if (!v.owasp?.id) continue;
  const weight = { critical: 10, high: 6, medium: 3, low: 1, info: 0 }[v.severity] || 0;
  owaspContribution.set(v.owasp.id, (owaspContribution.get(v.owasp.id) || 0) + weight);
}
const topOwasp = [...owaspContribution.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3).map(([id]) => id);

let deltaText = "";
if (priorScan) {
  const priorCritical = (priorScan.critical ?? 0);
  const deltaCritical = counts.critical - priorCritical;
  const priorDate = new Date(priorScan.started_at || priorScan.startedAt).toLocaleDateString("fr-FR");
  deltaText = deltaCritical === 0
    ? ` Par rapport au scan précédent du ${priorDate}, le nombre de vulnérabilités critiques est stable.`
    : ` ${deltaCritical > 0 ? "+" : ""}${deltaCritical} critique(s) depuis le dernier scan du ${priorDate}.`;
}

const summaryText = `Ce rapport présente les résultats d'un scan automatisé de <strong>${escapeHtml(scan.url || "")}</strong>
  effectué le ${date}. Au total, <strong>${scan.vulnerabilities.length}</strong> vulnérabilité(s)
  ont été identifiées, dont <strong>${counts.critical}</strong> critique(s) et <strong>${counts.high}</strong> élevée(s).
  Le score de risque calculé est de <strong>${score}</strong>, niveau : <strong>${risk.label}</strong>.${deltaText}
  ${topOwasp.length ? `Catégories OWASP les plus contributrices au score de risque : <strong>${topOwasp.join(", ")}</strong>.` : ""}`;
```
Replace the `<div class="summary">...</div>` block's hardcoded inner text with `${summaryText}`.

(Note on `priorScan.critical`/`priorScan.started_at`: this is the shape `GET /history/list` returns — confirmed in `database/db.py`'s `list_scans()`, which selects `critical`/`started_at` as bare columns from the `scans` table, snake_case, NOT the camelCase `criticalCount`/`startedAt` the live `currentScan` object uses. Don't assume camelCase here; this object comes from the backend's own list endpoint, not from `chrome.storage.local.scanHistory`.)

- [ ] **Step 3: Verify**

Run: `node --check extension/src/devtools/panel.js`
Expected: no output.

Hand-trace: with no prior scan (`priorScan === null`), confirm `deltaText === ""` and the summary reads sensibly without a dangling "stable" or delta clause. With a prior scan showing fewer criticals, confirm the `+N critique(s)` phrasing. With zero OWASP-tagged findings, confirm the final sentence is omitted entirely (not rendered as "Catégories OWASP... : ").

- [ ] **Step 4: Commit**

```bash
git add extension/src/devtools/panel.js
git commit -m "feat(extension): data-driven executive summary in the HTML export

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Remediation snippets

**Why this task exists:** per spec §4.4 — `taxonomy.js` entries have no remediation guidance beyond the generic `recommendation` string each module already sets; a short, concrete code example (a parameterized query for `sqli`, a CSP header for `missing-header`) for the highest-volume types is the kind of thing that makes a report actionable rather than just descriptive.

**Files:**
- Modify: `extension/src/utils/taxonomy.js` (5 entries gain `remediationSnippet`; `enrichFinding()` merge logic)
- Modify: `extension/src/devtools/panel.js` (`buildCardHtml`, `buildHTMLReport`, `buildSARIF`)

**Interfaces:**
- Modifies: `TAXONOMY["sqli"|"xss"|"missing-header"|"insecure-cookie"|"outdated-library"]` each gain an optional `remediationSnippet: string` field (a short code example, plain text, no markup). `enrichFinding(v)` is extended to merge it the same way every other optional taxonomy field already is (`v.remediationSnippet || tax.remediationSnippet`) — confirmed by reading the current function body first: it already has this exact pattern for `title`/`owasp`/`cwe`/`cvssBase`/`cvssVector`/`impact`/`references`; add one more line following the identical style, do not restructure the function.
- Consumes (SARIF): Task 3's `buildSARIF`'s `results[]` mapping — extend it so a result gains `fixes: [{ description: { text: v.remediationSnippet } }]` only when `v.remediationSnippet` is present (SARIF's own `fixes` is optional per-result, omit the key entirely rather than setting it to an empty array when there's nothing to put there).

- [ ] **Step 1: Add the 5 snippets to `taxonomy.js`**

Add a `remediationSnippet` field to exactly these 5 entries (find each by its existing key, add the field inside its object, don't touch any other entry):
```javascript
// "sqli" entry gains:
remediationSnippet: "// Toujours des requêtes paramétrées, jamais de concatenation :\nconst rows = await db.query('SELECT * FROM users WHERE id = ?', [userId]);",

// "xss" entry gains:
remediationSnippet: "// Échapper systématiquement la sortie, ou utiliser un framework qui le fait par défaut :\nelement.textContent = userInput; // jamais innerHTML = userInput",

// "missing-header" entry gains:
remediationSnippet: "Content-Security-Policy: default-src 'self'; script-src 'self'\nX-Content-Type-Options: nosniff\nX-Frame-Options: DENY",

// "insecure-cookie" entry gains:
remediationSnippet: "Set-Cookie: session=...; Secure; HttpOnly; SameSite=Strict",

// "outdated-library" entry gains:
remediationSnippet: "# Mettre à jour vers la dernière version stable, puis vérifier via :\nnpm audit fix\n# ou l'équivalent du gestionnaire de paquets utilisé",
```

- [ ] **Step 2: Extend `enrichFinding`'s merge**

In `taxonomy.js`'s `enrichFinding(v)`, add one line following the exact pattern of the existing optional-field merges: `remediationSnippet: v.remediationSnippet || tax.remediationSnippet,`.

- [ ] **Step 3: Render it on the card**

In `buildCardHtml` (`panel.js`), add a new `card-section` (same pattern as the existing "⚠️ Impact" section) shown only when present:
```javascript
${v.remediationSnippet ? `
  <div class="card-section">
    <div class="section-label">🔧 Exemple de correction</div>
    <div class="section-content"><pre style="font-family:monospace;font-size:11px;white-space:pre-wrap;background:var(--bg-0);padding:8px;border-radius:6px;color:var(--text-1)">${escapeHtml(v.remediationSnippet)}</pre></div>
  </div>` : ""}
```

- [ ] **Step 4: Render it in the HTML export**

In `buildHTMLReport`'s row template, add a 13th column (header `<th>Correction</th>` added to the `<thead>` row too) rendering `${v.remediationSnippet ? `<pre>${escapeHtml(v.remediationSnippet)}</pre>` : "—"}` — reuse the existing `pre{...}` CSS rule already defined in this function's `<style>` block, no new styling needed.

**Note on sequencing:** Task 2 already modified this same row template's LAST existing cell (adding a `<details>` block inside the evidence `<td>`). This step adds a brand-new 13th `<td>` AFTER whatever cells exist once Task 2 has landed — read the actual current row template first, don't assume the pre-Task-2 column count or content.

- [ ] **Step 5: Extend `buildSARIF`'s mapping (Task 3's function)**

In `buildSARIF`'s `results.map(...)`, change each result object to conditionally include `fixes`:
```javascript
results: scan.vulnerabilities.map(v => ({
  ruleId: v.type || "unknown",
  level: sarifLevelFor(v.severity),
  message: { text: v.description || v.title || v.type || "Finding" },
  locations: [{ physicalLocation: { artifactLocation: { uri: v.url || scan.url || "" } } }],
  ...(v.remediationSnippet ? { fixes: [{ description: { text: v.remediationSnippet } }] } : {}),
})),
```

- [ ] **Step 6: Verify**

Run: `node --check extension/src/devtools/panel.js extension/src/utils/taxonomy.js`
Expected: no output.

Hand-trace (Review Focus #5): construct a `remediationSnippet` value containing `<script>alert(1)</script>` (even though the 5 real snippets above never contain this, the field is still attacker-adjacent in principle since a module could theoretically set it from a `cwe`-style merge path — verify the ESCAPING mechanism, not just today's hardcoded content) and confirm it renders fully HTML-entity-escaped in the card, the HTML export's new column, and is NOT run through any escaping in the SARIF JSON (SARIF is JSON, not HTML — `JSON.stringify` already handles this correctly; confirm you haven't added a redundant/incorrect HTML-escape inside the SARIF path, which would double-escape and corrupt the text for a CI consumer).

- [ ] **Step 7: Commit**

```bash
git add extension/src/utils/taxonomy.js extension/src/devtools/panel.js
git commit -m "feat(extension): remediation snippets for sqli/xss/missing-header/insecure-cookie/outdated-library

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 6: Risk-trend sparkline

**Why this task exists:** per spec §4.5 — the `scans` table already has `score` and `started_at` per URL (confirmed: `database/db.py`'s schema has both columns, plus `idx_scans_url`/`idx_scans_started_at` indexes already in place), but nothing queries them as a trend; a small sparkline is the simplest way to show "is this target getting better or worse" without a charting dependency.

**Files:**
- Modify: `backend/database/db.py` (`risk_trend`)
- Modify: `backend/routes/history.py` (new route)
- Test: `backend/tests/test_risk_trend.py` (new)
- Modify: `extension/src/devtools/panel.js` (`renderHistory`, `buildHTMLReport`, `exportReport`)

**Interfaces:**
- Produces: `database/db.py::risk_trend(url: str, limit: int = 10) -> List[Dict[str, Any]]` — `[{"started_at": int, "score": int}, ...]`, oldest first (chronological order, ready to plot left-to-right), at most `limit` most recent scans for that exact `url`.
- Produces (route): `GET /history/trend?url=<url>&limit=10` → `{"trend": [...]}` (same shape as `risk_trend`'s return, JSON-wrapped).
- Produces (extension): `buildSparklineSvg(points)` — takes `[{started_at, score}, ...]`, returns a small inline `<svg>` polyline string (same "no charting dependency" approach as the existing donut), or an empty-state string when `points.length < 2` (Review Focus #4).

- [ ] **Step 1: Write the failing test (backend)**

```python
# backend/tests/test_risk_trend.py
import time
from database.db import init_db, save_scan, risk_trend

def test_risk_trend_returns_chronological_scores_for_url(tmp_path, monkeypatch):
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test.db"))
    init_db()

    base = int(time.time() * 1000)
    for i, score in enumerate([10, 25, 5]):
        save_scan({
            "id": f"scan-{i}", "url": "http://example.com/",
            "startedAt": base + i * 1000, "finishedAt": base + i * 1000,
            "vulnerabilities": [{"severity": "critical"}] * (score // 10) + [{"severity": "low"}] * (score % 10),
        })

    trend = risk_trend("http://example.com/", limit=10)
    assert [t["started_at"] for t in trend] == [base, base + 1000, base + 2000]
    assert len(trend) == 3


def test_risk_trend_empty_for_unknown_url(tmp_path, monkeypatch):
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test2.db"))
    init_db()
    assert risk_trend("http://never-scanned.example/", limit=10) == []
```
(The exact `score` values from `[10, 25, 5]` via finding-count tricks are a convenience to get distinguishable scores through the existing `_stats()`/`SEVERITY_WEIGHT` logic — if the resulting scores don't land exactly on 10/25/5 once run against the real weight table, adjust the test's finding lists to whatever combination produces 3 distinct, ordered scores; the assertion that matters is the `started_at` ordering, not the exact score values.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cd backend && pytest tests/test_risk_trend.py -v`
Expected: FAIL — `ImportError` or `AttributeError: module 'database.db' has no attribute 'risk_trend'`.

- [ ] **Step 3: Implement `risk_trend`**

In `database/db.py`, add:
```python
def risk_trend(url: str, limit: int = 10) -> List[Dict[str, Any]]:
    with _lock, _connect() as conn:
        rows = conn.execute("""
            SELECT started_at, score FROM scans
            WHERE url = ? ORDER BY started_at DESC LIMIT ?
        """, (url, limit)).fetchall()
        return [{"started_at": r["started_at"], "score": r["score"]} for r in reversed(rows)]
```
(`reversed(rows)` turns the DESC-ordered SQL result back into chronological/oldest-first order for a left-to-right sparkline — don't reorder in SQL with `ASC` + a subquery, this is simpler and the test above pins the expected order.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cd backend && pytest tests/test_risk_trend.py -v`
Expected: PASS (both tests). Also run `cd backend && pytest tests/ -v` to confirm no regression.

- [ ] **Step 5: Add the route**

In `routes/history.py`, add:
```python
@history_bp.route("/trend", methods=["GET"])
def trend():
    url = request.args.get("url")
    if not url:
        return jsonify({"error": "url requis"}), 400
    limit = int(request.args.get("limit", 10))
    return jsonify({"trend": risk_trend(url, limit=limit)})
```
(Add `risk_trend` to the existing `from database.db import ...` line at the top of the file — don't duplicate the import statement.)

- [ ] **Step 6: Build the sparkline and wire it into the Historique tab**

In `panel.js`, add:
```javascript
function buildSparklineSvg(points) {
  if (!points || points.length < 2) {
    return `<span style="font-size:10px;color:var(--text-3)">Historique insuffisant</span>`;
  }
  const scores = points.map(p => p.score);
  const min = Math.min(...scores), max = Math.max(...scores);
  const range = max - min || 1;
  const w = 60, h = 20;
  const coords = points.map((p, i) => {
    const x = (i / (points.length - 1)) * w;
    const y = h - ((p.score - min) / range) * h;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(" ");
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline points="${coords}" fill="none" stroke="var(--accent)" stroke-width="1.5"/></svg>`;
}

async function fetchRiskTrend(url) {
  try {
    const cfg = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
    if (!cfg || cfg.error) return [];
    const r = await fetch(`${cfg.backendUrl}/history/trend?url=${encodeURIComponent(url)}&limit=10`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return [];
    const data = await r.json();
    return data.trend || [];
  } catch (e) {
    return [];
  }
}
```
(**Correction, caught during Task 4's review:** `panel.js` has no `DEFAULT_CONFIG` symbol at all — it's a plain `<script>`, not a module, and every config read in this file goes through `chrome.runtime.sendMessage({type:"GET_CONFIG"})` instead, same pattern `fetchPriorScanForSummary` (Task 4) already uses. The code above reflects that correction; do not use `DEFAULT_CONFIG`/`chrome.storage.local.get("config")` directly in `panel.js`.)
In `renderHistory()`, after building `el.innerHTML` from the mapped rows (the existing `.join("")` call), fetch the trend ONCE per distinct `url` among the currently-rendered `scanHistory` entries (deduplicate via a `Map`/`Set` first — do not issue one backend call per row when several rows share the same URL) and inject each result into a new placeholder element per row (e.g. give each `.history-row` a `<span class="sparkline-slot" data-url="${escapeHtml(s.url)}"></span>` in the template, then after render, loop the distinct URLs, `fetchRiskTrend`, and set `.innerHTML` on every slot matching that URL).

- [ ] **Step 7: Wire it into the HTML export header**

In `exportReport`, alongside Task 4's `fetchPriorScanForSummary` call, also call `const trendPoints = await fetchRiskTrend(scan.url);` and pass it to `buildHTMLReport(scan, forPrint, priorScan, trendPoints)` (now a 4th parameter). In `buildHTMLReport`'s `<header>` block, add `<div style="margin-left:auto">${buildSparklineSvg(trendPoints)}</div>` (or similar placement — your call, consistent with the header's existing flex layout).

- [ ] **Step 8: Verify**

Run: `cd backend && pytest tests/ -v` (confirm 115+ passing, no regression) and `node --check extension/src/devtools/panel.js`.

Hand-trace (Review Focus #4): call `buildSparklineSvg([])` and `buildSparklineSvg([{started_at: 1, score: 5}])` (zero and one point) — confirm both return the "Historique insuffisant" state, never throw on `Math.min(...[])` (`Math.min()` with no args is `Infinity`, which would silently corrupt a 1-point case if the length check were wrong — confirm the `< 2` guard, not `< 1`, is what's actually written).

- [ ] **Step 9: Commit**

```bash
git add backend/database/db.py backend/routes/history.py backend/tests/test_risk_trend.py extension/src/devtools/panel.js
git commit -m "feat: risk-trend sparkline per URL (Historique tab + HTML export header)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 7: PDF print CSS polish

**Why this task exists:** per spec §4.6 — no approach change (browser print stays, non-objectif §1), just two concrete CSS fixes: the table header should repeat on every printed page, and a finding row should never be split across a page break.

**Files:**
- Modify: `extension/src/devtools/panel.js` (`buildHTMLReport`'s `<style>` block, `@media print` rule)

**Interfaces:**
- Modifies: the `@media print` rule inside `buildHTMLReport`'s inline `<style>` block only — no other function touched.

- [ ] **Step 1: Add `page-break-inside: avoid` to table rows**

In the `@media print {...}` block, add `tr{page-break-inside:avoid}` alongside the existing `body{padding:15px}.no-print{display:none}table{font-size:9.5px}pre{max-height:none}` rules.

- [ ] **Step 2: Confirm header repetition**

The table already uses a proper `<thead>`/`<tbody>` structure (confirmed by reading the existing markup) — Chrome's print engine repeats `<thead>` content across pages for a multi-page `<table>` by default, with no extra CSS required, AS LONG AS nothing wraps the table in a fixed-height/`overflow:auto` container (confirmed there isn't one: `buildHTMLReport` produces a single flat, non-scrolling document). No CSS change needed for this half of the requirement — this step is a verification step only, not an implementation step.

Verify by hand: generate a report with enough findings to span 2+ printed pages (or simulate by checking the rendered static HTML's structure directly — confirm `<thead>` is a sibling of `<tbody>`, not nested inside it or hidden by any CSS that would prevent the browser's native repeat-header-on-each-page behavior).

- [ ] **Step 3: Verify**

Run: `node --check extension/src/devtools/panel.js`
Expected: no output.

- [ ] **Step 4: Commit**

```bash
git add extension/src/devtools/panel.js
git commit -m "fix(extension): avoid splitting a finding row across a printed page

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Final verification (whole Round 8)

- [ ] Run the full backend suite: `cd backend && pytest tests/ -v` — expect all tests green (114 from Round 7 + the new `test_risk_trend.py` tests from Task 6).
- [ ] `node --check` every modified `.js` file in one pass: `node --check extension/src/devtools/panel.js extension/src/utils/constants.js extension/src/utils/taxonomy.js` (`panel.html` is also modified this round but isn't JS and has no syntax checker — review it by eye).
- [ ] Manually load the unpacked extension in real Chrome, run a scan, and confirm: unchecking "Inclure les faux positifs" after marking one finding as a false positive excludes it from every export format; a SARIF file downloads and is valid JSON with the expected `runs[].results[]` shape; the HTML export's summary paragraph reads differently for a URL with vs. without scan history; a finding of type `sqli`/`xss`/`missing-header`/`insecure-cookie`/`outdated-library` shows a remediation snippet on its card and in the HTML/SARIF exports; the Historique tab shows a small sparkline per distinct URL (or the "Historique insuffisant" placeholder for a URL scanned only once); printing the HTML export to PDF doesn't split a finding row across a page.
