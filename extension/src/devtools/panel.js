// ================================================================
//  panel.js — Dashboard DevTools VulnScan (v1.2)
//  - Cartes pliables avec "Voir plus"
//  - Tabs Résultats / Historique
//  - Progression scan temps réel
//  - Affichage CVSS/CWE/OWASP/Impact/Recommandation/Références
// ================================================================

let allVulns       = [];
let currentDiscovery = null;  // { urls, forms, endpoints } — crawler discovery du dernier scan (Round 7)
let lastScanId     = null;
let expandedIds    = new Set();
let descExpandedIds = new Set();   // pour "Voir plus" des descriptions
let currentFilter  = "all";
let currentSearch  = "";
let currentTab     = "results";
let scanHistory    = [];
let cmpSelection   = new Set();  // ids des scans sélectionnés pour comparaison
let trafficExpandedIds = new Set();  // ids des lignes "Trafic" dépliées
let moduleLogLines = [];  // console d'activité par module (Round 7) — capée à 50 lignes

const SEVERITY_ORDER  = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_WEIGHT = { critical: 10, high: 6, medium: 3, low: 1, info: 0 };
const SEVERITY_LABEL  = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

const TYPE_LABEL = {
  "xss": "Cross-Site Scripting (XSS)",
  "sqli": "SQL Injection",
  "csrf": "Cross-Site Request Forgery",
  "outdated-library": "Vulnerable Component",
  "sensitive-data": "Sensitive Data Exposure",
  "missing-header": "Missing Security Header",
  "weak-csp": "Weak CSP",
  "info-disclosure": "Information Disclosure",
  "mixed-content": "Mixed Content",
  "open-redirect": "Open Redirect",
  "missing-sri": "Missing SRI",
  "insecure-cookie": "Insecure Cookie",
  "tls": "TLS / SSL",
  "path-traversal": "Path Traversal",
  "command-injection": "Command Injection",
};

// =====================================================
// Initialisation
// =====================================================
document.addEventListener("DOMContentLoaded", async () => {
  try {
    const tabId = chrome.devtools.inspectedWindow.tabId;
    chrome.tabs.get(tabId, (tab) => {
      document.getElementById("urlDisplay").textContent = tab.url ?? "—";
    });
  } catch {
    document.getElementById("urlDisplay").textContent = "URL inconnue";
  }

  await initTheme();
  await loadHistory();
  if (scanHistory.length > 0) {
    lastScanId = scanHistory[0].id;
    allVulns   = scanHistory[0].vulnerabilities || [];
    currentDiscovery = scanHistory[0].discovery || null;
    renderAll();
    updateScanMeta(scanHistory[0]);
    restoreModuleLog(scanHistory[0]);
  }

  setupEventListeners();
  setupRuntimeListeners();
  refreshBackendStatus();
});

async function loadHistory() {
  try {
    scanHistory = await chrome.runtime.sendMessage({ type: "GET_RESULTS" }) || [];
    renderHistory();
  } catch { scanHistory = []; }
}

// =====================================================
// Thème clair/sombre (Round 7, Task 8)
// =====================================================
// Unique lecture GET_CONFIG au démarrage : elle sert aussi à initialiser la case
// « Inclure les faux positifs » des exports (Round 8, Task 1).
async function initTheme() {
  let cfg;
  try {
    cfg = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
  } catch {
    cfg = null;
  }
  applyTheme(cfg?.theme === "light" ? "light" : "dark");
  const chkFP = document.getElementById("chkIncludeFP");
  if (chkFP) chkFP.checked = !!cfg?.includeFalsePositivesInExport;
}

// data-theme="light" active le bloc d'overrides CSS ; "dark" = pas d'attribut
// du tout, puisque les valeurs par défaut de :root sont déjà le thème sombre.
function applyTheme(theme) {
  if (theme === "light") {
    document.documentElement.dataset.theme = "light";
  } else {
    delete document.documentElement.dataset.theme;
  }
  const btn = document.getElementById("btnThemeToggle");
  if (btn) btn.textContent = theme === "light" ? "🌙" : "☀️";
}

async function onToggleTheme() {
  const next = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  applyTheme(next);
  try {
    const cfg = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
    if (!cfg || cfg.error) {
      console.warn("[VulnScan] GET_CONFIG invalide, SET_CONFIG (theme) annulé :", cfg?.error);
      return;
    }
    await chrome.runtime.sendMessage({ type: "SET_CONFIG", payload: { ...cfg, theme: next } });
  } catch (e) {
    console.warn("[VulnScan] SET_CONFIG (theme) KO :", e.message);
  }
}

// =====================================================
// Event listeners
// =====================================================
function setupEventListeners() {
  document.getElementById("btnScan").addEventListener("click", onStartScan);
  document.getElementById("btnStop").addEventListener("click", onStopScan);
  document.getElementById("btnClear").addEventListener("click", onClearResults);
  const btnTheme = document.getElementById("btnThemeToggle");
  if (btnTheme) btnTheme.addEventListener("click", onToggleTheme);

  document.getElementById("btnExportJson").addEventListener("click", () => exportReport("json"));
  document.getElementById("btnExportHtml").addEventListener("click", () => exportReport("html"));
  document.getElementById("btnExportCsv").addEventListener("click",  () => exportReport("csv"));
  document.getElementById("btnExportPdf").addEventListener("click",  () => exportReport("pdf"));
  const xmlBtn = document.getElementById("btnExportXml");
  if (xmlBtn) xmlBtn.addEventListener("click", () => exportReport("xml"));
  document.getElementById("btnExportSarif").addEventListener("click", () => exportReport("sarif"));
  document.getElementById("chkIncludeFP").addEventListener("change", async (e) => {
    const result = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
    if (!result || result.error) { console.warn("[VulnScan] GET_CONFIG KO, réglage non sauvegardé"); return; }
    await chrome.runtime.sendMessage({
      type: "SET_CONFIG",
      payload: { ...result, includeFalsePositivesInExport: e.target.checked },
    });
  });

  document.getElementById("searchInput").addEventListener("input", (e) => {
    currentSearch = e.target.value.toLowerCase().trim();
    renderCards();
  });

  document.querySelectorAll(".chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      currentFilter = chip.dataset.filter;
      renderCards();
    });
  });

  // Tabs
  document.querySelectorAll(".tab").forEach(tab => {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  });

  const btnRecheck = document.getElementById("btnRecheckBackend");
  if (btnRecheck) btnRecheck.addEventListener("click", refreshBackendStatus);

  // Boutons comparaison
  const btnCmp = document.getElementById("btnCompare");
  if (btnCmp) btnCmp.addEventListener("click", runDiff);
  const btnClearCmp = document.getElementById("btnClearCmp");
  if (btnClearCmp) btnClearCmp.addEventListener("click", () => {
    cmpSelection.clear();
    updateCmpHint();
    renderHistory();
  });
}

function setupRuntimeListeners() {
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === "VULN_FOUND") {
      if (!allVulns.find((v) => v.id === message.payload.id)) {
        allVulns.push(message.payload);
        renderAll();
      }
    }
    if (message.type === "SCAN_COMPLETED") {
      lastScanId = message.payload.id;
      allVulns   = message.payload.vulnerabilities || [];
      currentDiscovery = message.payload.discovery || null;
      renderAll();
      updateScanMeta(message.payload);
      // Fix 3 (final-fix-wave) : resynchronise le log d'activité sur la version
      // finale renvoyée par le backend (currentScan.moduleLog) — couvre le cas
      // où le panel a raté des MODULE_LOG en cours de scan (reconnexion DevTools).
      restoreModuleLog(message.payload);
      setScanningState(false);
      setStatus("ready", "Scan terminé");
      setScanProgress("Terminé", 100);
      // Note : seule la barre de progression se masque après 1.5s — la console
      // d'activité (#moduleLogWrap) est un conteneur séparé, non affecté.
      setTimeout(() => hideProgress(), 1500);
      loadHistory();
    }
    if (message.type === "SCAN_PROGRESS") {
      const stage = message.payload?.stage || "";
      const pct = stage === "passive" ? 35 : stage === "backend" ? 75 : 50;
      setScanProgress(message.payload?.label || "Scan...", pct);
    }
    if (message.type === "SCAN_ERROR") {
      setScanningState(false);
      setStatus("error", message.payload?.error || "Erreur de scan");
      hideProgress();
      alert("⚠️ Scan impossible :\n\n" + (message.payload?.error || "Erreur inconnue"));
    }
    if (message.type === "BACKEND_STATUS") {
      updateBackendUI(message.payload);
    }
    if (message.type === "MODULE_LOG") {
      appendModuleLog(message.payload || []);
    }
  });
}

// =====================================================
// Console d'activité par module (Round 7)
// Fix 3 (final-fix-wave) : le conteneur #moduleLogConsole vit maintenant HORS
// de #scanProgressWrap (voir panel.html) — il reste visible après la fin du
// scan au lieu de disparaître avec le setTimeout(hideProgress, 1500).
// Fix 5 (final-fix-wave) : un module qui a crashé (entry.status === "error")
// s'affiche avec un marqueur "✗" distinct, au lieu d'un "✓ ... 0 findings"
// indiscernable d'un module qui a simplement rien trouvé.
// =====================================================
function formatModuleLogLine(e) {
  if (e.status === "error") {
    return `✗ ${e.module} — erreur (${e.error || "inconnue"}) (${e.elapsedMs}ms)`;
  }
  return `✓ ${e.module} — ${e.findings} findings (${e.elapsedMs}ms)`;
}

function appendModuleLog(entries) {
  for (const e of entries) {
    moduleLogLines.push(formatModuleLogLine(e));
  }
  if (moduleLogLines.length > 50) {
    moduleLogLines = moduleLogLines.slice(moduleLogLines.length - 50);
  }
  renderModuleLog();
}

// Restaure le log d'activité à partir d'un scan stocké (historique, reconnexion
// du panel) — scan.moduleLog est le tableau brut renvoyé par le backend,
// stocké sur currentScan par le service-worker (Fix 3, point 2).
function restoreModuleLog(scan) {
  const entries = (scan && scan.moduleLog) || [];
  moduleLogLines = entries.map(formatModuleLogLine);
  if (moduleLogLines.length > 50) {
    moduleLogLines = moduleLogLines.slice(moduleLogLines.length - 50);
  }
  renderModuleLog();
}

function renderModuleLog() {
  const wrap = document.getElementById("moduleLogWrap");
  const el = document.getElementById("moduleLogConsole");
  if (!el || !wrap) return;
  if (moduleLogLines.length === 0) {
    wrap.classList.remove("visible");
    el.innerHTML = "";
    return;
  }
  wrap.classList.add("visible");
  el.innerHTML = moduleLogLines
    .map((line) => `<div class="module-log-line">${escapeHtml(line)}</div>`)
    .join("");
  el.scrollTop = el.scrollHeight;
}

function switchTab(name) {
  currentTab = name;
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".tab-panel").forEach(p => p.classList.toggle("active", p.dataset.tabPanel === name));
  if (name === "history") loadHistory();
  if (name === "traffic") renderTraffic();
  if (name === "surface") renderSurface();
  if (name === "modules") renderModuleList();
}

// =====================================================
// Backend status
// =====================================================
async function refreshBackendStatus() {
  try {
    const status = await chrome.runtime.sendMessage({ type: "RECHECK_BACKEND" });
    updateBackendUI(status);
  } catch {}
}

function updateBackendUI(status) {
  const banner = document.getElementById("backendBanner");
  const dot = document.getElementById("backendStatusDot");
  const label = document.getElementById("backendStatusLabel");
  const errSpan = document.getElementById("backendBannerError");

  if (status && status.available) {
    if (banner) banner.style.display = "none";
    if (dot) dot.className = "status-dot ready";
    if (label) label.textContent = `Backend : v${status.version}`;
  } else {
    if (banner) banner.style.display = "block";
    if (dot) dot.className = "status-dot error";
    if (label) label.textContent = "Backend : KO";
    if (errSpan) errSpan.textContent = status?.error ? `(${status.error})` : "";
  }
}

// =====================================================
// Actions
// =====================================================
async function onStartScan() {
  try {
    const tabId = chrome.devtools.inspectedWindow.tabId;
    const tab   = await chrome.tabs.get(tabId);
    allVulns = [];
    // Final fix wave (Fix 2) : le scan précédemment affiché n'est plus celui à
    // l'écran — sans ce reset, un export en cours de scan retrouverait l'ancien
    // scan dans scanHistory et en reprendrait l'URL. SCAN_COMPLETED le repositionne.
    lastScanId = null;
    currentDiscovery = null;
    expandedIds.clear();
    descExpandedIds.clear();
    moduleLogLines = [];
    renderModuleLog();
    renderAll();
    setStatus("scanning", "Initialisation...");
    setScanningState(true);
    showProgress();
    setScanProgress("Vérification backend...", 10);

    const result = await chrome.runtime.sendMessage({
      type: "START_SCAN",
      payload: { tabId, url: tab.url },
    });
    if (result?.error) {
      setScanningState(false);
      setStatus("error", "Backend indisponible");
      hideProgress();
      alert("⚠️ Scan impossible :\n\n" + result.error);
      refreshBackendStatus();
      return;
    }
    lastScanId = result?.id ?? null;
  } catch (e) {
    setStatus("error", "Erreur : " + (e.message || "scan impossible"));
    setScanningState(false);
    hideProgress();
  }
}

async function onStopScan() {
  await chrome.runtime.sendMessage({ type: "STOP_SCAN" });
  setScanningState(false);
  setStatus("ready", "Scan arrêté");
  hideProgress();
}

function onClearResults() {
  allVulns = [];
  currentDiscovery = null;
  expandedIds.clear();
  descExpandedIds.clear();
  // Vide aussi la console d'activité : elle persiste après la fin d'un scan,
  // elle ne doit pas survivre à "Effacer" à côté de résultats désormais vides.
  moduleLogLines = [];
  renderModuleLog();
  renderAll();
  setStatus("ready", "Prêt");
  document.getElementById("scanMeta").textContent = "—";
}

// =====================================================
// Rendu global
// =====================================================
function renderAll() {
  renderKPI();
  renderDonut();
  renderTypes();
  renderCards();
  renderTraffic();
  renderSurface();
  updateFilterCounts();
}

function getFilteredVulns() {
  return allVulns.filter((v) => {
    if (currentFilter === "false_positive") {
      if (v.triageStatus !== "false_positive") return false;
    } else if (currentFilter !== "all" && v.severity !== currentFilter) {
      return false;
    }
    if (currentSearch) {
      const blob = [v.description, v.type, v.parameter, v.url, v.recommendation,
                    v.cwe?.id, v.owasp?.id, v.title, v.impact]
        .filter(Boolean).join(" ").toLowerCase();
      if (!blob.includes(currentSearch)) return false;
    }
    return true;
  });
}

function countBySeverity(arr) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of arr) {
    if (v.severity in counts) counts[v.severity]++;
  }
  return counts;
}

function computeRiskScore(counts) {
  return counts.critical * SEVERITY_WEIGHT.critical
       + counts.high     * SEVERITY_WEIGHT.high
       + counts.medium   * SEVERITY_WEIGHT.medium
       + counts.low      * SEVERITY_WEIGHT.low;
}

function riskLevel(score) {
  if (score === 0)  return { label: "Aucun risque",   color: "var(--low)" };
  if (score < 5)    return { label: "Risque faible",  color: "var(--low)" };
  if (score < 15)   return { label: "Risque modéré",  color: "var(--medium)" };
  if (score < 35)   return { label: "Risque élevé",   color: "var(--high)" };
  return                  { label: "Risque critique", color: "var(--critical)" };
}

// =====================================================
// KPI
// =====================================================
function renderKPI() {
  const counts = countBySeverity(allVulns);
  const total  = allVulns.length;
  const score  = computeRiskScore(counts);
  const risk   = riskLevel(score);

  document.getElementById("kpiTotal").textContent    = total;
  document.getElementById("kpiCritical").textContent = counts.critical;
  document.getElementById("kpiHigh").textContent     = counts.high;
  document.getElementById("kpiMedium").textContent   = counts.medium;
  document.getElementById("kpiLow").textContent      = counts.low;
  document.getElementById("kpiInfo").textContent     = counts.info;

  document.getElementById("kpiScore").innerHTML =
    `Score risque : <strong style="color:${risk.color}">${score}</strong> — ${risk.label}`;

  // Compteurs des onglets
  document.getElementById("tabResultCount").textContent = total;
  document.getElementById("tabHistoryCount").textContent = scanHistory.length;
}

function updateFilterCounts() {
  const counts = countBySeverity(allVulns);
  document.getElementById("countAll").textContent       = allVulns.length;
  document.getElementById("countFCritical").textContent = counts.critical;
  document.getElementById("countFHigh").textContent     = counts.high;
  document.getElementById("countFMedium").textContent   = counts.medium;
  document.getElementById("countFLow").textContent      = counts.low;
  document.getElementById("countFInfo").textContent     = counts.info;
  document.getElementById("countFFalsePositive").textContent =
    allVulns.filter(v => v.triageStatus === "false_positive").length;
}

// =====================================================
// Donut + types (inchangés du round précédent)
// =====================================================
function renderDonut() {
  const counts = countBySeverity(allVulns);
  const total  = allVulns.length || 1;

  const segments = [
    { id: "donutCritical", value: counts.critical },
    { id: "donutHigh",     value: counts.high },
    { id: "donutMedium",   value: counts.medium },
    { id: "donutLow",      value: counts.low },
    { id: "donutInfo",     value: counts.info },
  ];

  let offset = 25;
  segments.forEach((s) => {
    const pct = (s.value / total) * 100;
    const el  = document.getElementById(s.id);
    if (el) {
      el.setAttribute("stroke-dasharray", `${pct} ${100 - pct}`);
      el.setAttribute("stroke-dashoffset", `${offset}`);
    }
    offset = (offset - pct + 100) % 100;
  });

  document.getElementById("donutCenterValue").textContent = allVulns.length;
  document.getElementById("legendCritical").textContent = counts.critical;
  document.getElementById("legendHigh").textContent     = counts.high;
  document.getElementById("legendMedium").textContent   = counts.medium;
  document.getElementById("legendLow").textContent      = counts.low;
  document.getElementById("legendInfo").textContent     = counts.info;
}

function renderTypes() {
  const list = document.getElementById("typesList");
  if (!list) return;
  if (allVulns.length === 0) {
    list.innerHTML = `<div class="type-row" style="color:var(--text-4);font-size:11px">Aucune donnée</div>`;
    return;
  }
  const counts = {};
  for (const v of allVulns) counts[v.type] = (counts[v.type] || 0) + 1;
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const max = sorted[0]?.[1] || 1;

  list.innerHTML = sorted.map(([type, count]) => {
    const label = TYPE_LABEL[type] || type;
    const pct = Math.round((count / max) * 100);
    return `
      <div class="type-row" style="flex-direction:column;align-items:stretch;gap:0">
        <div style="display:flex;justify-content:space-between;align-items:center;width:100%">
          <span class="type-name">${escapeHtml(label)}</span>
          <span class="type-count">${count}</span>
        </div>
        <div class="type-bar"><div class="type-bar-fill" style="width:${pct}%"></div></div>
      </div>`;
  }).join("");
}

// =====================================================
// CARDS (la nouveauté principale)
// =====================================================
function renderCards() {
  const container = document.getElementById("cardsContainer");
  const filtered = getFilteredVulns();

  if (filtered.length === 0) {
    container.innerHTML = `
      <div class="empty">
        <div class="empty-icon">${allVulns.length === 0 ? "🔎" : "🪄"}</div>
        <div>${allVulns.length === 0
          ? "Lancez un scan pour voir les vulnérabilités détectées sur la page courante."
          : "Aucune vulnérabilité ne correspond aux filtres."}</div>
      </div>`;
    return;
  }

  // Tri : sévérité puis confiance puis CVSS
  filtered.sort((a, b) => {
    const sa = SEVERITY_ORDER[a.severity] ?? 5;
    const sb = SEVERITY_ORDER[b.severity] ?? 5;
    if (sa !== sb) return sa - sb;
    if ((b.confidence ?? 0) !== (a.confidence ?? 0)) return (b.confidence ?? 0) - (a.confidence ?? 0);
    return (b.cvssBase ?? 0) - (a.cvssBase ?? 0);
  });

  container.innerHTML = filtered.map(buildCardHtml).join("");

  // Wire up clicks (event delegation aurait été plus efficace mais ok ici)
  container.querySelectorAll(".card-head").forEach(el => {
    el.addEventListener("click", () => toggleCard(el.dataset.id));
  });
  container.querySelectorAll(".voir-plus").forEach(el => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      toggleDesc(el.dataset.id);
    });
  });
  container.querySelectorAll(".copy-btn").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      try {
        await navigator.clipboard.writeText(btn.dataset.copy);
        const orig = btn.textContent;
        btn.textContent = "✓ Copié";
        setTimeout(() => { btn.textContent = orig; }, 1200);
      } catch {}
    });
  });
  container.querySelectorAll(".triage-btn").forEach(btn => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = btn.dataset.id;
      const status = btn.dataset.status;
      const result = await chrome.runtime.sendMessage({
        type: "SET_TRIAGE",
        payload: { scanId: lastScanId, findingId: id, status },
      });
      if (result?.success) {
        const v = allVulns.find(x => x.id === id);
        if (v) v.triageStatus = status;
        renderCards();
        updateFilterCounts();
      } else {
        alert("Triage non enregistré : " + (result?.error || "erreur inconnue"));
      }
    });
  });
}

function buildCardHtml(v) {
  const isOpen = expandedIds.has(v.id);
  const isDescOpen = descExpandedIds.has(v.id);
  const typeLabel = v.title || TYPE_LABEL[v.type] || v.type;
  const desc = v.description || "";
  const isLongDesc = desc.length > 140;
  const date = v.detectedAt ? new Date(v.detectedAt).toLocaleTimeString("fr-FR") : "—";

  const cvss = v.cvssBase ?? null;
  const cvssColor = cvss == null ? "var(--text-3)"
    : cvss >= 9 ? "var(--sev-text-critical)"
    : cvss >= 7 ? "var(--sev-text-high)"
    : cvss >= 4 ? "var(--sev-text-medium)"
    : "var(--sev-text-low)";

  return `
    <div class="vuln-card sev-${v.severity} ${isOpen ? "expanded" : ""} ${v.triageStatus === "false_positive" ? "triaged-fp" : ""}" data-id="${v.id}">
      <div class="card-head" data-id="${v.id}">
        <span class="card-toggle">▶</span>
        <div class="card-head-main">
          <div class="card-head-title">
            <span class="badge badge-${v.severity}">${SEVERITY_LABEL[v.severity]}</span>
            <strong>${escapeHtml(typeLabel)}</strong>
            ${v.cwe?.id ? `<span class="badge badge-neutral">${v.cwe.id}</span>` : ""}
            ${v.owasp?.id ? `<span class="badge badge-neutral">${v.owasp.id}</span>` : ""}
            ${v.confidence != null ? `<span class="badge badge-neutral">Conf. ${v.confidence}%</span>` : ""}
          </div>
          <div class="card-head-desc ${isDescOpen || !isLongDesc ? "" : "collapsed"}">${escapeHtml(desc)}</div>
          ${isLongDesc ? `<button class="voir-plus" data-id="${v.id}">${isDescOpen ? "− Voir moins" : "+ Voir plus"}</button>` : ""}
          <div class="card-head-meta" style="margin-top:8px">
            ${v.parameter ? `<span><b>Param :</b> ${escapeHtml(v.parameter).slice(0, 60)}</span>` : ""}
            <span><b>Détecté :</b> ${date}</span>
            <span><b>Source :</b> ${escapeHtml(v.source || v.scanMode || "passive")}</span>
          </div>
        </div>
      </div>

      <div class="card-body">
        ${cvss != null ? `
          <div class="card-section">
            <div class="section-label">Score CVSS v3.1</div>
            <div class="cvss-bar">
              <div class="cvss-bar-track"><div class="cvss-bar-fill" style="width:${(cvss / 10) * 100}%;background:${cvssColor}"></div></div>
              <div class="cvss-value" style="color:${cvssColor}">${cvss.toFixed(1)}</div>
            </div>
            ${v.cvssVector ? `<div class="section-content" style="margin-top:6px;font-family:monospace;font-size:11px;color:var(--text-3)">${escapeHtml(v.cvssVector)}</div>` : ""}
          </div>` : ""}

        ${v.impact ? `
          <div class="card-section">
            <div class="section-label">⚠️ Impact</div>
            <div class="section-content">${escapeHtml(v.impact)}</div>
          </div>` : ""}

        ${v.url ? `
          <div class="card-section">
            <div class="section-label">URL concernée
              <button class="copy-btn" data-copy="${escapeAttr(v.url)}">Copier</button>
            </div>
            <div class="section-content" style="font-family:monospace;font-size:11.5px;color:var(--text-2);word-break:break-all">${escapeHtml(v.url)}</div>
          </div>` : ""}

        ${v.payload ? `
          <div class="card-section">
            <div class="section-label">💉 Payload utilisé
              <button class="copy-btn" data-copy="${escapeAttr(v.payload)}">Copier</button>
            </div>
            <div class="evidence">${escapeHtml(v.payload)}</div>
          </div>` : ""}

        ${v.evidence ? `
          <div class="card-section">
            <div class="section-label">🔍 Preuve trouvée
              <button class="copy-btn" data-copy="${escapeAttr(v.evidence)}">Copier</button>
            </div>
            <div class="evidence">${escapeHtml(v.evidence)}</div>
          </div>` : ""}

        ${v.detectionMethod ? `
          <div class="card-section">
            <div class="section-label">🛠 Méthode de détection</div>
            <div class="section-content">${escapeHtml(v.detectionMethod)}</div>
          </div>` : ""}

        ${v.recommendation ? `
          <div class="card-section">
            <div class="section-label">💡 Recommandation</div>
            <div class="section-content">${escapeHtml(v.recommendation)}</div>
          </div>` : ""}

        ${v.remediationSnippet ? `
          <div class="card-section">
            <div class="section-label">🔧 Exemple de correction</div>
            <div class="section-content"><pre style="font-family:monospace;font-size:11px;white-space:pre-wrap;background:var(--bg-0);padding:8px;border-radius:6px;color:var(--text-1)">${escapeHtml(v.remediationSnippet)}</pre></div>
          </div>` : ""}

        <div class="card-section">
          <div class="section-label">📚 Références</div>
          <div class="ref-grid">
            ${v.owasp ? `
              <div class="ref-item">
                <div class="ref-key">OWASP Top 10</div>
                <div class="ref-val"><a href="${v.owasp.url}" target="_blank">${v.owasp.id} — ${escapeHtml(v.owasp.name)}</a></div>
              </div>` : ""}
            ${v.cwe ? `
              <div class="ref-item">
                <div class="ref-key">CWE</div>
                <div class="ref-val"><a href="${v.cwe.url}" target="_blank">${v.cwe.id} — ${escapeHtml(v.cwe.name)}</a></div>
              </div>` : ""}
            ${(v.references || []).map(r => `
              <div class="ref-item">
                <div class="ref-key">Lien externe</div>
                <div class="ref-val"><a href="${r.url}" target="_blank">${escapeHtml(r.label)}</a></div>
              </div>`).join("")}
          </div>
        </div>

        <div class="card-section">
          <div class="section-label">Triage</div>
          <div class="section-content" style="display:flex;gap:8px">
            <button class="btn btn-secondary triage-btn" data-id="${v.id}" data-status="confirmed" style="font-size:11px;padding:4px 10px">✓ Confirmé</button>
            <button class="btn btn-secondary triage-btn" data-id="${v.id}" data-status="false_positive" style="font-size:11px;padding:4px 10px">✕ Faux positif</button>
          </div>
        </div>
      </div>
    </div>`;
}

function toggleCard(id) {
  if (expandedIds.has(id)) expandedIds.delete(id);
  else expandedIds.add(id);
  renderCards();
}

function toggleDesc(id) {
  if (descExpandedIds.has(id)) descExpandedIds.delete(id);
  else descExpandedIds.add(id);
  renderCards();
}

// =====================================================
// Historique
// =====================================================
function renderHistory() {
  const el = document.getElementById("historyList");
  if (!el) return;
  if (!scanHistory || scanHistory.length === 0) {
    el.innerHTML = `<div class="empty"><div class="empty-icon">🕘</div><div>Aucun scan dans l'historique.</div></div>`;
    updateCmpHint();
    return;
  }
  el.innerHTML = scanHistory.map(s => {
    const counts = countBySeverity(s.vulnerabilities || []);
    const date = new Date(s.startedAt).toLocaleString("fr-FR");
    const checked = cmpSelection.has(s.id) ? "checked" : "";
    return `
      <div class="history-row" data-id="${s.id}" style="grid-template-columns:30px 1fr 80px 80px 70px 70px">
        <input type="checkbox" class="cmp-check" data-id="${s.id}" ${checked} style="width:18px;height:18px;accent-color:var(--accent);cursor:pointer">
        <div class="hist-info">
          <div class="history-url">${escapeHtml(s.url || "—")}</div>
          <div class="history-meta">${date} · ${s.id.slice(0, 8)} · ${(s.vulnerabilities || []).length} vulns</div>
        </div>
        <div>
          <div class="history-stat" style="color:var(--sev-text-critical)">${counts.critical}</div>
          <div class="history-stat-label">Critical</div>
        </div>
        <div>
          <div class="history-stat" style="color:var(--sev-text-high)">${counts.high}</div>
          <div class="history-stat-label">High</div>
        </div>
        <div>
          <div class="history-stat" style="color:var(--text-2)">${(s.vulnerabilities || []).length}</div>
          <div class="history-stat-label">Total</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:center">
          <span class="sparkline-slot" data-url="${escapeHtml(s.url)}"></span>
        </div>
      </div>`;
  }).join("");

  // Tendance de risque : une requête backend par URL distincte, pas par ligne
  const distinctUrls = Array.from(new Set(scanHistory.map(s => s.url).filter(Boolean)));
  distinctUrls.forEach(async (url) => {
    const points = await fetchRiskTrend(url);
    const svg = buildSparklineSvg(points);
    el.querySelectorAll(".sparkline-slot").forEach(slot => {
      if (slot.dataset.url === url) slot.innerHTML = svg;
    });
  });

  // Clic sur la ligne (ailleurs que sur la checkbox) → ouvre le scan
  el.querySelectorAll(".history-row").forEach(row => {
    row.querySelector(".hist-info").addEventListener("click", () => {
      const id = row.dataset.id;
      const scan = scanHistory.find(s => s.id === id);
      if (scan) {
        lastScanId = scan.id;
        allVulns = scan.vulnerabilities || [];
        currentDiscovery = scan.discovery || null;
        renderAll();
        updateScanMeta(scan);
        restoreModuleLog(scan);
        switchTab("results");
      }
    });
  });

  // Checkboxes → sélection comparaison
  el.querySelectorAll(".cmp-check").forEach(cb => {
    cb.addEventListener("change", (e) => {
      const id = cb.dataset.id;
      if (cb.checked) {
        if (cmpSelection.size >= 2) {
          // Décocher le premier
          const first = Array.from(cmpSelection)[0];
          cmpSelection.delete(first);
        }
        cmpSelection.add(id);
      } else {
        cmpSelection.delete(id);
      }
      updateCmpHint();
      renderHistory();
    });
  });
  updateCmpHint();
}

function updateCmpHint() {
  const hint = document.getElementById("cmpHint");
  const btn  = document.getElementById("btnCompare");
  if (!hint || !btn) return;
  hint.textContent = cmpSelection.size === 0 ? "" :
                     cmpSelection.size === 1 ? "1 scan sélectionné — choisissez le 2e" :
                     "2 scans sélectionnés — prêt à comparer";
  btn.disabled = cmpSelection.size !== 2;
}

// =====================================================
// Comparaison de 2 scans (diff)
// =====================================================
async function runDiff() {
  if (cmpSelection.size !== 2) return;
  const [a, b] = Array.from(cmpSelection).sort((x, y) => {
    const sa = scanHistory.find(s => s.id === x)?.startedAt || 0;
    const sb = scanHistory.find(s => s.id === y)?.startedAt || 0;
    return sa - sb;
  });

  // Calcul local du diff (pas besoin du backend pour ça)
  const scanA = scanHistory.find(s => s.id === a);
  const scanB = scanHistory.find(s => s.id === b);
  if (!scanA || !scanB) return;

  const key = (f) => `${f.type}|${(f.parameter || "").slice(0, 80)}|${f.url || ""}`;
  const aMap = new Map((scanA.vulnerabilities || []).map(f => [key(f), f]));
  const bMap = new Map((scanB.vulnerabilities || []).map(f => [key(f), f]));

  const added   = [];
  const removed = [];
  const changed = [];
  const stable  = [];

  for (const [k, f] of bMap) {
    if (!aMap.has(k)) added.push(f);
    else {
      const fa = aMap.get(k);
      if (fa.severity !== f.severity || fa.cvssBase !== f.cvssBase) {
        changed.push({ before: fa, after: f });
      } else stable.push(f);
    }
  }
  for (const [k, f] of aMap) {
    if (!bMap.has(k)) removed.push(f);
  }

  renderDiff(scanA, scanB, { added, removed, changed, stable });
  switchTab("diff");
}

function renderDiff(scanA, scanB, diff) {
  const el = document.getElementById("diffContent");
  const dateA = new Date(scanA.startedAt).toLocaleString("fr-FR");
  const dateB = new Date(scanB.startedAt).toLocaleString("fr-FR");

  const card = (f, action) => {
    const sev = f.severity || "info";
    const accentColor = action === "added"   ? "var(--critical)"
                       : action === "removed" ? "var(--low)"
                       : "var(--medium)";
    const textColor = action === "added"   ? "var(--sev-text-critical)"
                     : action === "removed" ? "var(--sev-text-low)"
                     : "var(--sev-text-medium)";
    return `
      <div class="vuln-card sev-${sev}" style="margin-bottom:8px;border-left-color:${accentColor}">
        <div class="card-head" style="cursor:default">
          <span style="font-size:14px;font-weight:700;color:${textColor};margin-right:8px;">
            ${action === "added" ? "+" : action === "removed" ? "−" : "Δ"}
          </span>
          <div class="card-head-main">
            <div class="card-head-title">
              <span class="badge badge-${sev}">${SEVERITY_LABEL[sev]}</span>
              <strong>${escapeHtml(f.title || TYPE_LABEL[f.type] || f.type)}</strong>
              ${f.cwe?.id ? `<span class="badge badge-neutral">${f.cwe.id}</span>` : ""}
            </div>
            <div class="card-head-desc">${escapeHtml(f.description || "")}</div>
            ${f.parameter ? `<div class="card-head-meta" style="margin-top:6px"><span><b>Param :</b> ${escapeHtml(f.parameter).slice(0, 80)}</span></div>` : ""}
          </div>
        </div>
      </div>`;
  };

  const changedCard = (c) => {
    const sev = c.after.severity;
    return `
      <div class="vuln-card sev-${sev}" style="margin-bottom:8px;border-left-color:var(--medium)">
        <div class="card-head" style="cursor:default">
          <span style="font-size:14px;font-weight:700;color:var(--sev-text-medium);margin-right:8px">Δ</span>
          <div class="card-head-main">
            <div class="card-head-title">
              <strong>${escapeHtml(c.after.title || TYPE_LABEL[c.after.type] || c.after.type)}</strong>
            </div>
            <div class="card-head-desc">
              Sévérité : <span class="badge badge-${c.before.severity}">${SEVERITY_LABEL[c.before.severity]}</span>
              → <span class="badge badge-${c.after.severity}">${SEVERITY_LABEL[c.after.severity]}</span>
              ${c.before.cvssBase != null && c.after.cvssBase != null ?
                `· CVSS ${c.before.cvssBase.toFixed(1)} → ${c.after.cvssBase.toFixed(1)}` : ""}
            </div>
          </div>
        </div>
      </div>`;
  };

  el.innerHTML = `
    <div style="margin-bottom:18px;display:grid;grid-template-columns:1fr auto 1fr;gap:14px;align-items:center">
      <div style="background:var(--bg-2);padding:14px;border-radius:8px;border-left:3px solid var(--accent)">
        <div style="font-size:10px;font-weight:700;color:var(--text-3);text-transform:uppercase">Scan A (avant)</div>
        <div style="font-size:13px;color:var(--text-1);margin-top:4px">${escapeHtml(scanA.url || "—")}</div>
        <div style="font-size:11px;color:var(--text-3);margin-top:2px">${dateA} · ${(scanA.vulnerabilities || []).length} vulns</div>
      </div>
      <div style="font-size:28px;color:var(--accent)">→</div>
      <div style="background:var(--bg-2);padding:14px;border-radius:8px;border-left:3px solid #8b5cf6">
        <div style="font-size:10px;font-weight:700;color:var(--text-3);text-transform:uppercase">Scan B (après)</div>
        <div style="font-size:13px;color:var(--text-1);margin-top:4px">${escapeHtml(scanB.url || "—")}</div>
        <div style="font-size:11px;color:var(--text-3);margin-top:2px">${dateB} · ${(scanB.vulnerabilities || []).length} vulns</div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px">
      <div style="background:rgba(239,68,68,0.12);padding:12px;border-radius:8px;border-left:3px solid #ef4444">
        <div style="font-size:24px;font-weight:800;color:var(--sev-text-critical)">+${diff.added.length}</div>
        <div style="font-size:11px;color:var(--text-3);text-transform:uppercase;font-weight:700">Nouveaux</div>
      </div>
      <div style="background:rgba(34,197,94,0.12);padding:12px;border-radius:8px;border-left:3px solid #22c55e">
        <div style="font-size:24px;font-weight:800;color:var(--sev-text-low)">−${diff.removed.length}</div>
        <div style="font-size:11px;color:var(--text-3);text-transform:uppercase;font-weight:700">Corrigés</div>
      </div>
      <div style="background:rgba(234,179,8,0.12);padding:12px;border-radius:8px;border-left:3px solid #eab308">
        <div style="font-size:24px;font-weight:800;color:var(--sev-text-medium)">${diff.changed.length}</div>
        <div style="font-size:11px;color:var(--text-3);text-transform:uppercase;font-weight:700">Modifiés</div>
      </div>
      <div style="background:var(--bg-2);padding:12px;border-radius:8px;border-left:3px solid var(--text-3)">
        <div style="font-size:24px;font-weight:800;color:var(--text-2)">${diff.stable.length}</div>
        <div style="font-size:11px;color:var(--text-3);text-transform:uppercase;font-weight:700">Stables</div>
      </div>
    </div>

    ${diff.added.length > 0 ? `<h3 style="font-size:13px;text-transform:uppercase;letter-spacing:0.05em;color:var(--sev-text-critical);margin:18px 0 10px">+ Nouvelles vulnérabilités (régressions)</h3>${diff.added.map(f => card(f, "added")).join("")}` : ""}

    ${diff.removed.length > 0 ? `<h3 style="font-size:13px;text-transform:uppercase;letter-spacing:0.05em;color:var(--sev-text-low);margin:18px 0 10px">− Vulnérabilités corrigées</h3>${diff.removed.map(f => card(f, "removed")).join("")}` : ""}

    ${diff.changed.length > 0 ? `<h3 style="font-size:13px;text-transform:uppercase;letter-spacing:0.05em;color:var(--sev-text-medium);margin:18px 0 10px">Δ Vulnérabilités modifiées</h3>${diff.changed.map(changedCard).join("")}` : ""}
  `;
}

// =====================================================
// TRAFIC (preuves requête/réponse HTTP capturées — Round 7)
// =====================================================
function renderTraffic() {
  const list = document.getElementById("trafficList");
  const countEl = document.getElementById("tabTrafficCount");
  if (!list) return;

  const filtered = allVulns.filter(v => v.evidenceRequest);

  if (countEl) countEl.textContent = filtered.length;

  if (filtered.length === 0) {
    list.innerHTML = `
      <div class="empty">
        <div class="empty-icon">🌐</div>
        <div>Aucune requête HTTP capturée pour l'instant.</div>
      </div>`;
    return;
  }

  list.innerHTML = filtered.map(buildTrafficRowHtml).join("");

  list.querySelectorAll(".traffic-row-head").forEach(el => {
    el.addEventListener("click", () => toggleTrafficRow(el.dataset.id));
  });
}

function toggleTrafficRow(id) {
  if (trafficExpandedIds.has(id)) trafficExpandedIds.delete(id);
  else trafficExpandedIds.add(id);
  renderTraffic();
}

// Rend un objet headers {Name: value} en lignes "Name: value", chaque partie échappée
// individuellement (noms ET valeurs sont des données réseau non fiables).
function formatHeadersForDisplay(headers) {
  return Object.entries(headers || {})
    .map(([name, value]) => `${escapeHtml(name)}: ${escapeHtml(value)}`)
    .join("\n");
}

// Le corps capturé peut être une chaîne (opts.data) ou un objet JSON (opts.json) ou absent.
function formatBodyForDisplay(body) {
  if (body == null) return "";
  if (typeof body === "string") return body;
  try {
    return JSON.stringify(body);
  } catch {
    return String(body);
  }
}

function buildRequestRawHtml(req) {
  const parts = [`${escapeHtml(req.method || "")} ${escapeHtml(req.url || "")}`];
  const headers = formatHeadersForDisplay(req.headers);
  if (headers) parts.push(headers);
  const body = formatBodyForDisplay(req.body);
  if (body) parts.push(escapeHtml(body));
  return parts.join("\n\n");
}

function buildResponseRawHtml(resp) {
  const parts = [escapeHtml(resp.status != null ? String(resp.status) : "—")];
  const headers = formatHeadersForDisplay(resp.headers);
  if (headers) parts.push(headers);
  if (resp.body_snippet) parts.push(escapeHtml(resp.body_snippet));
  return parts.join("\n\n");
}

function buildTrafficRowHtml(v) {
  const req = v.evidenceRequest || {};
  const resp = v.evidenceResponse || {};
  const isOpen = trafficExpandedIds.has(v.id);
  const typeLabel = v.title || TYPE_LABEL[v.type] || v.type;

  return `
    <div class="vuln-card sev-${v.severity} ${isOpen ? "expanded" : ""}" data-id="${v.id}">
      <div class="card-head traffic-row-head" data-id="${v.id}">
        <span class="card-toggle">▶</span>
        <div class="card-head-main">
          <div class="card-head-title">
            <span class="badge badge-neutral">${escapeHtml(req.method || "?")}</span>
            <span class="badge badge-neutral">${escapeHtml(resp.status != null ? String(resp.status) : "—")}</span>
            <span class="badge badge-${v.severity}">${SEVERITY_LABEL[v.severity] || v.severity}</span>
            <strong>${escapeHtml(typeLabel)}</strong>
          </div>
          <div class="card-head-meta" style="margin-top:6px">
            <span style="font-family:monospace;font-size:11.5px;color:var(--text-2);word-break:break-all">${escapeHtml(req.url || "")}</span>
            ${resp.elapsed_ms != null ? `<span><b>Latence :</b> ${escapeHtml(String(resp.elapsed_ms))} ms</span>` : ""}
          </div>
        </div>
      </div>

      <div class="card-body">
        <div class="card-section">
          <div class="ref-grid">
            <div>
              <div class="section-label">➡ Requête</div>
              <div class="evidence">${buildRequestRawHtml(req)}</div>
            </div>
            <div>
              <div class="section-label">⬅ Réponse</div>
              <div class="evidence">${buildResponseRawHtml(resp)}</div>
            </div>
          </div>
        </div>
      </div>
    </div>`;
}

// =====================================================
// SURFACE (attack surface découverte par le crawler : pages, formulaires,
// endpoints API — Round 7). Toutes les valeurs ci-dessous proviennent de la
// cible scannée (données non fiables) et DOIVENT passer par escapeHtml().
// Les valeurs de champs de formulaire ne sont JAMAIS affichées (name/type
// uniquement) — voir le point de revue dédié de cette tâche.
// =====================================================
function renderSurface() {
  const container = document.getElementById("surfaceContent");
  const countEl = document.getElementById("tabSurfaceCount");
  if (!container) return;

  const discovery = currentDiscovery || {};
  const urls = discovery.urls || [];
  const forms = discovery.forms || [];
  const endpoints = discovery.endpoints || [];
  const total = urls.length + forms.length + endpoints.length;

  if (countEl) countEl.textContent = total;

  if (total === 0) {
    container.innerHTML = `
      <div class="empty">
        <div class="empty-icon">🗺</div>
        <div>Aucune découverte pour l'instant. Lancez un scan avec les tests actifs activés pour cartographier la surface d'attaque.</div>
      </div>`;
    return;
  }

  const vulnCountForUrl = (u) => allVulns.filter((v) => v.url === u).length;

  container.innerHTML = `
    <div class="cards-container">
      ${buildSurfaceGroupHtml("📄 Pages découvertes", urls, () => buildSurfaceUrlListHtml(urls, vulnCountForUrl))}
      ${buildSurfaceGroupHtml("📝 Formulaires détectés", forms, () => buildSurfaceFormsHtml(forms))}
      ${buildSurfaceGroupHtml("🔌 Endpoints API", endpoints, () => buildSurfaceUrlListHtml(endpoints, vulnCountForUrl))}
    </div>`;
}

function buildSurfaceGroupHtml(label, items, buildBodyHtml) {
  return `
    <div class="group-header" style="margin:0 -14px">${label} <span class="group-count">${items.length}</span></div>
    ${items.length === 0
      ? `<div style="padding:10px 14px;color:var(--text-4);font-size:11.5px">Aucun élément détecté.</div>`
      : buildBodyHtml()}`;
}

function buildSurfaceUrlListHtml(items, vulnCountFn) {
  return items.map((u) => {
    const count = vulnCountFn(u);
    return `
      <div class="type-row" style="margin:6px 0">
        <span class="type-name" style="font-family:monospace;font-size:11.5px;word-break:break-all;font-weight:400">${escapeHtml(u)}</span>
        <span class="type-count">${count > 0 ? `${count} vuln${count > 1 ? "s" : ""}` : "—"}</span>
      </div>`;
  }).join("");
}

// Affiche uniquement action/method/field.name/field.type — ne JAMAIS rendre field.value.
function buildSurfaceFormsHtml(forms) {
  return forms.map((form, idx) => {
    const fields = form.fields || [];
    const fieldsHtml = fields.length > 0
      ? fields.map((f) =>
          `<span class="badge badge-neutral" style="margin:3px 4px 0 0;display:inline-block">${escapeHtml(f.name || "?")} <span style="opacity:.65">(${escapeHtml(f.type || "text")})</span></span>`
        ).join("")
      : `<span style="color:var(--text-4);font-size:11px">Aucun champ</span>`;
    return `
      <div class="card" style="margin:6px 0">
        <div class="card-label">
          <span>${escapeHtml(form.method || "GET")} · ${escapeHtml(form.id || ("form-" + idx))}</span>
        </div>
        <div class="card-value" style="font-family:monospace;font-size:11.5px;word-break:break-all;margin-bottom:8px">${escapeHtml(form.action || "—")}</div>
        <div>${fieldsHtml}</div>
      </div>`;
  }).join("");
}

// =====================================================
// MODULES (sélecteur fin des modules de scan actif — Round 7).
// Remplace le profil "Custom" historique à 5 cases (Options). Les cases cochées
// reflètent ce que le prochain scan exécutera RÉELLEMENT, pour tous les profils :
// preset (quick/standard/deep/owasp/api, "standard" par défaut) -> sa liste ;
// "custom" + cfg.customModules tableau (éventuellement [] = zéro module) -> ce
// tableau ; "custom" + cfg.customModules null/absent -> l'ensemble legacy (5 cases
// historiques + liste fixe). Calcul fait UNE seule fois, côté service-worker, par
// resolveEnabledModules() — demandé via le message GET_ENABLED_MODULES, la même
// fonction qu'utilise runActiveModules(), pour éviter toute divergence d'affichage.
// Les métadonnées viennent de GET /scanner/modules (backend interne, pas de
// données issues de la cible scannée) — escapeHtml() par prudence quand même.
//
// Fix 1 (final-fix-wave) : cocher/décocher une case ici bascule automatiquement
// cfg.scanProfile sur "custom" (voir onModuleCheckboxChange) — sinon la sélection
// n'a aucun effet tant que le profil actif (Options) n'est pas déjà "Custom".
// =====================================================
async function renderModuleList() {
  const container = document.getElementById("moduleList");
  if (!container) return;

  let cfg;
  try {
    cfg = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
  } catch {
    cfg = null;
  }
  if (!cfg) {
    container.innerHTML = `<div class="empty"><div class="empty-icon">⚙</div><div>Impossible de lire la configuration.</div></div>`;
    return;
  }

  let modules;
  try {
    const r = await fetch(`${cfg.backendUrl}/scanner/modules`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    modules = data.modules || [];
  } catch (e) {
    container.innerHTML = `<div class="empty"><div class="empty-icon">⚙</div><div>Backend indisponible — impossible de charger la liste des modules (${escapeHtml(e.message)}).</div></div>`;
    return;
  }

  if (modules.length === 0) {
    container.innerHTML = `<div class="empty"><div class="empty-icon">⚙</div><div>Aucun module disponible.</div></div>`;
    return;
  }

  // Cases cochées = exactement ce que le prochain scan exécutera, quel que soit
  // le profil actif (preset, custom configuré, ou custom jamais configuré) :
  // GET_ENABLED_MODULES appelle resolveEnabledModules(), la même fonction que
  // runActiveModules() côté service-worker. Rien n'est écrit dans la config ici.
  // Garde : si la réponse n'est pas un vrai tableau (ex. {error: ...} renvoyé
  // par le routeur de messages, ou sendMessage qui rejette), on n'appelle pas
  // new Set() dessus — on affiche l'erreur au lieu d'un faux état coché.
  let enabledModules;
  let enabledError = null;
  try {
    enabledModules = await chrome.runtime.sendMessage({ type: "GET_ENABLED_MODULES" });
  } catch (e) {
    enabledError = e.message;
  }
  if (!Array.isArray(enabledModules)) {
    const reason = enabledError || enabledModules?.error || "réponse invalide";
    console.warn("[VulnScan] GET_ENABLED_MODULES invalide :", reason);
    container.innerHTML = `<div class="empty"><div class="empty-icon">⚙</div><div>Impossible de déterminer les modules actifs (${escapeHtml(reason)}).</div></div>`;
    return;
  }
  const activeSet = new Set(enabledModules);

  const byCategory = new Map();
  for (const m of modules) {
    const cat = m.category || "autre";
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat).push(m);
  }

  container.innerHTML = [...byCategory.entries()].map(([cat, mods]) => `
    <div class="group-header" style="margin:0 -14px">${escapeHtml(cat)} <span class="group-count">${mods.length}</span></div>
    ${mods.map((m) => {
      const checked = activeSet.has(m.name);
      return `
        <div class="card" style="margin:6px 0;padding:10px 14px">
          <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer">
            <input type="checkbox" class="module-checkbox" data-module="${escapeHtml(m.name)}" ${checked ? "checked" : ""} style="margin-top:3px">
            <span style="flex:1">
              <span style="display:block;font-size:12.5px;font-weight:600;color:var(--text-1)">${escapeHtml(m.title || m.name)}</span>
              ${m.description ? `<span style="display:block;font-size:11px;color:var(--text-3);margin-top:2px">${escapeHtml(m.description)}</span>` : ""}
            </span>
          </label>
        </div>`;
    }).join("")}
  `).join("");

  container.querySelectorAll(".module-checkbox").forEach((cb) => {
    cb.addEventListener("change", onModuleCheckboxChange);
  });
}

async function onModuleCheckboxChange() {
  const checkedNames = [...document.querySelectorAll(".module-checkbox:checked")].map((cb) => cb.dataset.module);
  try {
    const cfg = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
    if (!cfg || cfg.error) {
      console.warn("[VulnScan] GET_CONFIG invalide, SET_CONFIG (customModules) annulé :", cfg?.error);
      return;
    }
    // Fix 1 (final-fix-wave) : basculer automatiquement sur le profil "Custom" —
    // sinon la sélection ci-dessus n'a aucun effet tant qu'un autre profil est actif.
    await chrome.runtime.sendMessage({
      type: "SET_CONFIG",
      payload: { ...cfg, customModules: checkedNames, scanProfile: "custom" },
    });
  } catch (e) {
    console.warn("[VulnScan] SET_CONFIG (customModules) KO :", e.message);
  }
}

// =====================================================
// EXPORT (JSON / CSV / HTML / PDF / XML)
// =====================================================
// Round 8, Task 4 : récupère le scan précédent de la même URL (s'il existe) pour
// alimenter le résumé exécutif data-driven du rapport HTML/PDF. Appelée depuis
// exportReport avant buildHTMLReport — reste un fetch isolé et nommé car le
// Task 6 y fera référence par son nom pour ajouter son propre pré-fetch.
// Final fix wave (Fix 2) : le filtre `url` de /history/list est un LIKE '%url%'
// (sous-chaîne) — on ne s'y fie que comme pré-filtre et on garde côté client
// uniquement l'URL exactement égale ET strictement antérieure au scan exporté
// (sinon un scan de http://site.com/login, ou un scan plus récent quand on
// exporte un ancien scan rouvert depuis l'Historique, pouvait servir de
// « précédent »). limit=100 : la liste backend est triée du plus récent au plus
// ancien, la borne doit donc dépasser tous les scans plus récents de même
// sous-chaîne pour atteindre le précédent d'un ancien scan rouvert (l'Historique
// en garde 50 par défaut) — même borne que fetchHistoryFromBackend.
async function fetchPriorScanForSummary(url, excludeId, currentStartedAt) {
  try {
    const cfg = await chrome.runtime.sendMessage({ type: "GET_CONFIG" });
    if (!cfg || cfg.error) return null;
    const r = await fetch(`${cfg.backendUrl}/history/list?url=${encodeURIComponent(url)}&limit=100`, { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return null;
    const data = await r.json();
    const matches = (data.scans || []).filter(s =>
      s.url === url && s.id !== excludeId && (s.started_at ?? s.startedAt) < currentStartedAt
    );
    // scans are already ordered started_at DESC from the backend, so the first
    // exact match after filtering is the most recent one strictly before this scan
    return matches[0] || null;
  } catch (e) {
    return null;
  }
}

// Round 8, Task 6 : mini-graphique SVG en polyligne (même approche "sans lib de
// charting" que le donut existant) à partir des points { started_at, score } de
// risk_trend. Moins de 2 points (0 ou 1 scan pour cette URL) → état neutre, jamais
// de crash sur Math.min(...[]) (Review Focus #4).
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

// Round 8, Task 6 : tendance de risque (score par scan, le plus ancien en premier)
// pour une URL donnée — alimente la sparkline de l'onglet Historique et de l'en-tête
// du rapport HTML/PDF.
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

async function exportReport(format) {
  if (allVulns.length === 0) {
    alert("Aucune vulnérabilité à exporter. Lancez d'abord un scan.");
    return;
  }
  // Point de filtrage unique (Round 8, Task 1) : appliqué avant le dispatch par
  // format, donc identique pour JSON/CSV/HTML/XML/PDF (et SARIF plus tard).
  const includeFP = document.getElementById("chkIncludeFP")?.checked ?? false;
  const vulnsToExport = includeFP ? allVulns : allVulns.filter(v => v.triageStatus !== "false_positive");
  // Final fix wave (Fix 2) : l'URL (et l'horodatage de référence du résumé) viennent
  // du scan réellement ouvert, pas de #urlDisplay (onglet inspecté à l'ouverture du
  // panel) — un ancien scan rouvert depuis l'Historique peut viser une autre URL.
  // Repli sur #urlDisplay seulement si le scan n'est pas (encore) dans scanHistory.
  const openScan = scanHistory.find(s => s.id === lastScanId);
  const scan = {
    id: lastScanId || crypto.randomUUID(),
    url: (openScan?.url) || document.getElementById("urlDisplay").textContent || "",
    startedAt: allVulns[0]?.detectedAt || Date.now(),
    finishedAt: Date.now(),
    vulnerabilities: vulnsToExport,
  };
  // started_at côté backend = currentScan.startedAt du service worker : on compare
  // donc à la même valeur (même source d'horloge) quand le scan est connu, et à
  // scan.startedAt (detectedAt de la 1re vuln, >= début du scan) sinon.
  const currentStartedAt = openScan?.startedAt ?? scan.startedAt;
  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  const baseName = `vulnscan-${stamp}`;

  try {
    if (format === "json") {
      downloadBlob(JSON.stringify(scan, null, 2), `${baseName}.json`, "application/json");
    } else if (format === "csv") {
      downloadBlob(buildCSV(scan), `${baseName}.csv`, "text/csv;charset=utf-8");
    } else if (format === "html") {
      const priorScan = await fetchPriorScanForSummary(scan.url, scan.id, currentStartedAt);
      const trendPoints = await fetchRiskTrend(scan.url);
      downloadBlob(buildHTMLReport(scan, false, priorScan, trendPoints), `${baseName}.html`, "text/html;charset=utf-8");
    } else if (format === "xml") {
      downloadBlob(buildXML(scan), `${baseName}.xml`, "application/xml");
    } else if (format === "sarif") {
      downloadBlob(buildSARIF(scan), `${baseName}.sarif`, "application/sarif+json");
    } else if (format === "pdf") {
      const priorScan = await fetchPriorScanForSummary(scan.url, scan.id, currentStartedAt);
      const trendPoints = await fetchRiskTrend(scan.url);
      openPrintTab(buildHTMLReport(scan, true, priorScan, trendPoints));
    }
    setStatus("ready", `Rapport ${format.toUpperCase()} prêt`);
  } catch (e) {
    console.error("[VulnScan] Export error:", e);
    alert("Erreur lors de l'export : " + e.message);
    setStatus("error", "Erreur export");
  }
}

function downloadBlob(content, filename, mimeType) {
  // Utilise chrome.downloads.download — fiable depuis un DevTools panel
  // (le truc <a download>.click() est souvent bloqué dans ce contexte).
  try {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    chrome.downloads.download({ url, filename, saveAs: false }, (downloadId) => {
      if (chrome.runtime.lastError) {
        console.error("[VulnScan] downloads.download error:", chrome.runtime.lastError);
        // Fallback : ancien <a> click
        const a = document.createElement("a");
        a.href = url; a.download = filename;
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
      }
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    });
  } catch (e) {
    console.error("[VulnScan] Export error:", e);
    alert("Erreur export : " + e.message);
  }
}

function openPrintTab(html) {
  // Utilise chrome.tabs.create — fiable depuis un DevTools panel
  // (window.open est souvent bloqué dans ce contexte).
  try {
    const blob = new Blob([html], { type: "text/html" });
    const url = URL.createObjectURL(blob);
    chrome.tabs.create({ url }, () => {
      if (chrome.runtime.lastError) {
        console.error("[VulnScan] tabs.create error:", chrome.runtime.lastError);
        const win = window.open(url, "_blank");
        if (!win) {
          alert("Impossible d'ouvrir le PDF. Vérifiez les permissions de l'extension.");
        }
      }
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    });
  } catch (e) {
    console.error("[VulnScan] Print tab error:", e);
    alert("Erreur ouverture PDF : " + e.message);
  }
}

function buildCSV(scan) {
  const headers = ["URL","Type","Titre","Severite","CVSS","CWE","OWASP","Confiance","Parametre","Payload","Description","Recommandation","Preuve","Impact"];
  const esc = (s) => `"${String(s ?? "").replace(/"/g, '""')}"`;
  const rows = scan.vulnerabilities.map(v => [
    v.url, v.type, v.title, v.severity, v.cvssBase,
    v.cwe?.id, v.owasp?.id, v.confidence,
    v.parameter, v.payload, v.description, v.recommendation,
    (v.evidence || "").slice(0, 200), v.impact,
  ].map(esc).join(","));
  return "﻿" + headers.join(",") + "\n" + rows.join("\n");
}

// Final fix wave (Fix 3) : un « ]]> » littéral dans un contenu capturé (cible
// scannée potentiellement hostile) fermerait la section CDATA avant l'heure et
// permettrait d'injecter de la structure XML — on le scinde en deux sections.
function cdataSafe(s) {
  return String(s ?? "").replace(/]]>/g, "]]]]><![CDATA[>");
}

function buildXML(scan) {
  const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
  const counts = countBySeverity(scan.vulnerabilities);

  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<vulnscan-report version="1.2">\n';
  xml += `  <metadata>\n`;
  xml += `    <scan-id>${esc(scan.id)}</scan-id>\n`;
  xml += `    <url>${esc(scan.url)}</url>\n`;
  xml += `    <started-at>${new Date(scan.startedAt).toISOString()}</started-at>\n`;
  xml += `    <finished-at>${new Date(scan.finishedAt).toISOString()}</finished-at>\n`;
  xml += `    <total>${scan.vulnerabilities.length}</total>\n`;
  xml += `  </metadata>\n`;
  xml += `  <summary critical="${counts.critical}" high="${counts.high}" medium="${counts.medium}" low="${counts.low}" info="${counts.info}"/>\n`;
  xml += '  <findings>\n';
  for (const v of scan.vulnerabilities) {
    xml += `    <finding id="${esc(v.id)}" severity="${esc(v.severity)}" confidence="${v.confidence ?? ""}" cvss="${v.cvssBase ?? ""}">\n`;
    xml += `      <type>${esc(v.type)}</type>\n`;
    xml += `      <title>${esc(v.title || "")}</title>\n`;
    if (v.cwe)   xml += `      <cwe id="${esc(v.cwe.id)}" url="${esc(v.cwe.url)}">${esc(v.cwe.name)}</cwe>\n`;
    if (v.owasp) xml += `      <owasp id="${esc(v.owasp.id)}" url="${esc(v.owasp.url)}">${esc(v.owasp.name)}</owasp>\n`;
    xml += `      <url>${esc(v.url)}</url>\n`;
    if (v.parameter) xml += `      <parameter>${esc(v.parameter)}</parameter>\n`;
    if (v.payload)   xml += `      <payload><![CDATA[${cdataSafe(v.payload)}]]></payload>\n`;
    xml += `      <description>${esc(v.description)}</description>\n`;
    if (v.impact) xml += `      <impact>${esc(v.impact)}</impact>\n`;
    xml += `      <recommendation>${esc(v.recommendation)}</recommendation>\n`;
    if (v.evidence) xml += `      <evidence><![CDATA[${cdataSafe(v.evidence.slice(0, 1000))}]]></evidence>\n`;
    if (v.evidenceRequest) {
      xml += `      <evidence-request><![CDATA[${cdataSafe(JSON.stringify(v.evidenceRequest))}]]></evidence-request>\n`;
    }
    if (v.evidenceResponse) {
      xml += `      <evidence-response><![CDATA[${cdataSafe(JSON.stringify(v.evidenceResponse))}]]></evidence-response>\n`;
    }
    if (v.detectionMethod) xml += `      <detection-method>${esc(v.detectionMethod)}</detection-method>\n`;
    if (v.references && v.references.length) {
      xml += `      <references>\n`;
      for (const r of v.references) {
        xml += `        <reference url="${esc(r.url)}">${esc(r.label)}</reference>\n`;
      }
      xml += `      </references>\n`;
    }
    xml += '    </finding>\n';
  }
  xml += '  </findings>\n';
  xml += '</vulnscan-report>\n';
  return xml;
}

function sarifLevelFor(severity) {
  return severity === "critical" || severity === "high" ? "error"
       : severity === "medium" ? "warning"
       : "note";
}

function buildSARIF(scan) {
  return JSON.stringify({
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
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
        ...(v.remediationSnippet ? { properties: { remediationSnippet: v.remediationSnippet } } : {}),
      })),
    }],
  }, null, 2);
}

function buildHTMLReport(scan, forPrint, priorScan, trendPoints) {
  const counts = countBySeverity(scan.vulnerabilities);
  const score = computeRiskScore(counts);
  const risk = riskLevel(score);
  const date = new Date(scan.startedAt).toLocaleString("fr-FR");

  // Round 8, Task 4 : résumé exécutif data-driven — top 3 catégories OWASP par
  // contribution au score de risque, et delta vs. le scan précédent de la même
  // URL (s'il existe). priorScan vient de GET /history/list (backend SQLite) :
  // colonnes brutes snake_case (`critical`, `started_at`), pas le shape camelCase
  // de currentScan/scanHistory utilisé ailleurs dans ce fichier.
  const owaspContribution = new Map();
  for (const v of scan.vulnerabilities) {
    if (!v.owasp?.id) continue;
    const weight = SEVERITY_WEIGHT[v.severity] || 0;
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
    ${topOwasp.length ? `Catégories OWASP les plus contributrices au score de risque : <strong>${topOwasp.map(escapeHtml).join(", ")}</strong>.` : ""}`;

  const rows = scan.vulnerabilities
    .slice()
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
    .map(v => `
      <tr class="sev-${v.severity}">
        <td><span class="badge badge-${v.severity}">${SEVERITY_LABEL[v.severity] || v.severity}</span></td>
        <td><strong>${escapeHtml(v.title || TYPE_LABEL[v.type] || v.type)}</strong></td>
        <td>${v.cvssBase != null ? v.cvssBase.toFixed(1) : "—"}</td>
        <td>${v.cwe ? `<a href="${v.cwe.url}">${v.cwe.id}</a>` : "—"}</td>
        <td>${v.owasp ? `<a href="${v.owasp.url}">${v.owasp.id}</a>` : "—"}</td>
        <td>${v.confidence != null ? v.confidence + "%" : "—"}</td>
        <td><code>${escapeHtml(v.url || "")}</code></td>
        <td>${escapeHtml(v.parameter || "—")}</td>
        <td>${escapeHtml(v.description || "")}</td>
        <td>${escapeHtml(v.impact || "—")}</td>
        <td>${escapeHtml(v.recommendation || "")}</td>
        <td><pre>${escapeHtml((v.evidence || "").slice(0, 300))}</pre>${
          v.evidenceRequest || v.evidenceResponse
            ? `<details><summary style="cursor:pointer;color:#4f46e5;font-size:10px;margin-top:4px">Requête / Réponse capturée</summary><pre style="margin-top:4px">${escapeHtml(JSON.stringify({ request: v.evidenceRequest, response: v.evidenceResponse }, null, 2).slice(0, 2000))}</pre></details>`
            : ""
        }</td>
        <td>${v.remediationSnippet ? `<pre>${escapeHtml(v.remediationSnippet)}</pre>` : "—"}</td>
      </tr>`).join("");

  const autoPrint = forPrint ? `<script>window.addEventListener("load", () => setTimeout(() => window.print(), 300));<\/script>` : "";

  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<title>VulnScan — Rapport</title>
<style>
  :root{--accent:#4f46e5;--text-3:#64748b}
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,-apple-system,sans-serif;color:#1e293b;padding:30px;background:#fff}
  header{display:flex;align-items:center;gap:14px;border-bottom:3px solid #4f46e5;padding-bottom:14px;margin-bottom:20px}
  h1{color:#4f46e5;font-size:24px}
  h2{color:#1e293b;font-size:16px;margin:24px 0 12px;padding-bottom:6px;border-bottom:1px solid #e2e8f0}
  .meta{color:#64748b;font-size:13px;margin-top:4px}
  .kpis{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin:24px 0}
  .kpi{padding:12px;border-radius:8px;border-left:4px solid #cbd5e1;background:#f8fafc}
  .kpi .v{font-size:24px;font-weight:800}
  .kpi .l{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.06em}
  .kpi.crit{border-color:#ef4444}.kpi.crit .v{color:#ef4444}
  .kpi.high{border-color:#f97316}.kpi.high .v{color:#f97316}
  .kpi.med{border-color:#eab308}.kpi.med .v{color:#eab308}
  .kpi.low{border-color:#22c55e}.kpi.low .v{color:#22c55e}
  .kpi.info{border-color:#38bdf8}.kpi.info .v{color:#38bdf8}
  .kpi.tot{border-color:#4f46e5}.kpi.tot .v{color:#4f46e5}
  .risk{display:inline-block;padding:6px 14px;border-radius:6px;color:white;font-weight:700;font-size:13px}
  table{width:100%;border-collapse:collapse;margin-top:16px;font-size:11.5px}
  th,td{padding:8px 10px;border:1px solid #e2e8f0;text-align:left;vertical-align:top}
  th{background:#f1f5f9;font-weight:700;font-size:10.5px;text-transform:uppercase;letter-spacing:.05em;color:#475569}
  .badge{padding:3px 8px;border-radius:4px;font-size:10px;font-weight:700;text-transform:uppercase;white-space:nowrap}
  .badge-critical{background:#fee2e2;color:#991b1b}
  .badge-high{background:#ffedd5;color:#9a3412}
  .badge-medium{background:#fef9c3;color:#854d0e}
  .badge-low{background:#dcfce7;color:#166534}
  .badge-info{background:#dbeafe;color:#1e40af}
  code{font-family:monospace;font-size:11px;color:#475569;word-break:break-all}
  pre{font-family:monospace;font-size:10px;background:#0f172a;color:#cbd5e1;padding:6px 8px;border-radius:4px;white-space:pre-wrap;max-width:280px;max-height:120px;overflow:auto}
  a{color:#4f46e5}
  .summary{background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:14px;margin:16px 0;font-size:13px;line-height:1.6}
  footer{margin-top:30px;padding-top:14px;border-top:1px solid #e2e8f0;color:#94a3b8;font-size:11px;text-align:center}
  @media print {body{padding:15px}.no-print{display:none}table{font-size:9.5px}pre{max-height:none}tr{page-break-inside:avoid}}
</style>
</head><body>
<header>
  <div style="font-size:36px">🛡️</div>
  <div>
    <h1>VulnScan — Rapport de sécurité</h1>
    <div class="meta">
      <strong>URL :</strong> <code>${escapeHtml(scan.url || "")}</code> ·
      <strong>Date :</strong> ${date} ·
      <strong>Scan ID :</strong> ${scan.id.slice(0, 8)}
    </div>
  </div>
  <div style="margin-left:auto">${buildSparklineSvg(trendPoints)}</div>
</header>

<h2>Résumé exécutif</h2>
<div class="summary">${summaryText}</div>

<div class="kpis">
  <div class="kpi tot"><div class="v">${scan.vulnerabilities.length}</div><div class="l">Total</div></div>
  <div class="kpi crit"><div class="v">${counts.critical}</div><div class="l">Critical</div></div>
  <div class="kpi high"><div class="v">${counts.high}</div><div class="l">High</div></div>
  <div class="kpi med"><div class="v">${counts.medium}</div><div class="l">Medium</div></div>
  <div class="kpi low"><div class="v">${counts.low}</div><div class="l">Low</div></div>
  <div class="kpi info"><div class="v">${counts.info}</div><div class="l">Info</div></div>
</div>

<p><strong>Score de risque :</strong> <span class="risk" style="background:${risk.color}">${score} — ${risk.label}</span></p>

<h2>Détail des vulnérabilités</h2>
<table>
  <thead>
    <tr><th>Sévérité</th><th>Titre</th><th>CVSS</th><th>CWE</th><th>OWASP</th><th>Conf.</th><th>URL</th><th>Paramètre</th><th>Description</th><th>Impact</th><th>Recommandation</th><th>Preuve</th><th>Correction</th></tr>
  </thead>
  <tbody>${rows || '<tr><td colspan="13" style="text-align:center;color:#94a3b8;padding:20px">Aucune vulnérabilité</td></tr>'}</tbody>
</table>

<footer>
  Généré par VulnScan v1.2 — Web Vulnerability Scanner · OWASP Top 10 / CWE / CVSS v3.1<br>
  <button class="no-print" onclick="window.print()" style="margin-top:8px;padding:6px 14px;background:#4f46e5;color:white;border:none;border-radius:4px;cursor:pointer">🖨 Imprimer / Enregistrer en PDF</button>
</footer>
${autoPrint}
</body></html>`;
}

// =====================================================
// État scan + progression
// =====================================================
function setScanningState(scanning) {
  document.getElementById("btnScan").style.display = scanning ? "none" : "";
  document.getElementById("btnStop").style.display = scanning ? "" : "none";
}

function setStatus(state, label) {
  const dot = document.getElementById("statusDot");
  dot.classList.remove("scanning", "ready", "error");
  dot.classList.add(state);
  document.getElementById("scanStatus").textContent = label;
}

function showProgress() { document.getElementById("scanProgressWrap").classList.add("visible"); }
function hideProgress() { document.getElementById("scanProgressWrap").classList.remove("visible"); }
function setScanProgress(stage, pct) {
  document.getElementById("scanProgressStage").textContent = stage;
  document.getElementById("scanProgressPct").textContent = pct + "%";
  document.getElementById("scanProgressFill").style.width = pct + "%";
}

function updateScanMeta(scan) {
  if (!scan) return;
  const start = scan.startedAt ? new Date(scan.startedAt).toLocaleTimeString("fr-FR") : "—";
  const count = (scan.vulnerabilities || []).length;
  document.getElementById("scanMeta").textContent = `Scan #${scan.id?.slice(0, 8) || ""} · ${start} · ${count} vuln${count > 1 ? "s" : ""}`;
}

// =====================================================
// Helpers
// =====================================================
function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function escapeAttr(str) {
  return escapeHtml(str);
}
