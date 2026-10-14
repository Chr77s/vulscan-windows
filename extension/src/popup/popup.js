// ================================================================
//  popup.js — Logique de la popup VulnScan
//  Note : pas de "type=module" ici, script classique
//  Les fonctions d'export (CSV/XML/SARIF/HTML, SEVERITY_*, TYPE_LABEL, etc.)
//  viennent de utils/export-builders.js, chargé avant ce fichier dans
//  popup.html — partagé avec panel.js pour éviter la duplication.
// ================================================================

let isScanning = false;
let currentScanId = null;
let vulns = [];

// ---- Initialisation ----
document.addEventListener("DOMContentLoaded", async () => {
  await loadCurrentTab();
  await loadLastScan();
  await loadBackendStatus();
  setupListeners();
});

async function loadCurrentTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const el = document.getElementById("currentUrl");
  el.textContent = tab.url ?? "URL inconnue";
  el.title = tab.url ?? "";
}

async function loadLastScan() {
  const { scanHistory } = await chrome.storage.local.get("scanHistory");
  const history = scanHistory ?? [];
  if (history.length > 0) displayResults(history[0].vulnerabilities);
}

async function loadBackendStatus() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: "BACKEND_STATUS" });
    updateBackendIndicator(resp);
  } catch {}
}

function setupListeners() {
  document.getElementById("scanBtn").addEventListener("click", async () => {
    if (isScanning) await stopScan();
    else await startScan();
  });

  // Boutons d'export — utilisent chrome.downloads.download (fiable depuis popup)
  document.getElementById("btnExportHtml")?.addEventListener("click", () => doExport("html"));
  document.getElementById("btnExportJson")?.addEventListener("click", () => doExport("json"));
  document.getElementById("btnExportCsv")?.addEventListener("click",  () => doExport("csv"));
  document.getElementById("btnExportXml")?.addEventListener("click",  () => doExport("xml"));
  document.getElementById("btnExportSarif")?.addEventListener("click", () => doExport("sarif"));
  document.getElementById("btnExportPdf")?.addEventListener("click",  () => doExport("pdf"));

  document.getElementById("btnOptions")?.addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
    window.close();
  });

  chrome.runtime.onMessage.addListener((message) => {
    switch (message.type) {
      case "VULN_FOUND":
        vulns.push(message.payload);
        displayResults(vulns);
        break;
      case "SCAN_PROGRESS":
        updateProgress(message.payload.current, message.payload.total);
        break;
      case "SCAN_COMPLETED":
        onScanCompleted(message.payload);
        break;
      case "BACKEND_STATUS":
        updateBackendIndicator(message.payload);
        break;
    }
  });
}

async function startScan() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab.id || !tab.url) return;

  isScanning = true;
  vulns = [];
  setScanningUI(true);

  const result = await chrome.runtime.sendMessage({
    type: "START_SCAN",
    payload: { tabId: tab.id, url: tab.url },
  });

  currentScanId = result.id;
}

async function stopScan() {
  await chrome.runtime.sendMessage({ type: "STOP_SCAN" });
  isScanning = false;
  setScanningUI(false);
}

function onScanCompleted(scan) {
  isScanning = false;
  currentScanId = scan.id;
  setScanningUI(false);
  displayResults(scan.vulnerabilities);
}

function setScanningUI(scanning) {
  const btn = document.getElementById("scanBtn");
  const bar = document.getElementById("progressBar");
  btn.textContent = scanning ? "⏹ Arreter le scan" : "▶ Lancer un scan";
  btn.classList.toggle("running", scanning);
  bar.classList.toggle("visible", scanning);
  if (!scanning) {
    document.getElementById("progressFill").style.width = "100%";
    setTimeout(() => {
      bar.classList.remove("visible");
      document.getElementById("progressFill").style.width = "0%";
    }, 1000);
  }
}

function updateProgress(current, total) {
  const pct = total > 0 ? Math.round((current / total) * 100) : 0;
  document.getElementById("progressFill").style.width = pct + "%";
}

function displayResults(vulnerabilities) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const v of vulnerabilities) {
    if (v.severity in counts) counts[v.severity]++;
  }
  document.getElementById("countCritical").textContent = counts.critical;
  document.getElementById("countHigh").textContent     = counts.high;
  document.getElementById("countMedium").textContent   = counts.medium;
  document.getElementById("countLow").textContent      = counts.low;

  const list = document.getElementById("vulnList");
  if (vulnerabilities.length === 0) {
    list.innerHTML = `<div class="empty-state">Aucune vulnerabilite detectee.</div>`;
    return;
  }

  const sorted = [...vulnerabilities].sort((a, b) =>
    (SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5)
  );

  list.innerHTML = sorted.slice(0, 20).map((v, i) => `
    <div class="vuln-item" data-idx="${i}">
      <div class="vuln-badges">
        <span class="badge badge-${v.severity}">${v.severity}</span>
        <span class="badge" style="background:#1e293b;color:#64748b">${(v.type || "").slice(0, 14)}</span>
      </div>
      <div class="vuln-desc-wrap">
        <div class="vuln-desc">${escapeHtml(v.description || "")}</div>
        ${(v.parameter || v.cwe?.id || v.owasp?.id) ? `
          <div class="vuln-meta">
            <span class="vuln-meta-inner">
              ${v.cwe?.id ? `🏷 ${v.cwe.id} · ` : ""}
              ${v.owasp?.id ? `OWASP ${v.owasp.id} · ` : ""}
              ${v.parameter ? `Param : ${escapeHtml(v.parameter)} · ` : ""}
              ${v.confidence != null ? `Confiance ${v.confidence}%` : ""}
            </span>
          </div>` : ""}
      </div>
    </div>`).join("");

  // Clic = toggle expanded (texte complet) + double-clic = ouvre DevTools panel
  list.querySelectorAll(".vuln-item").forEach(el => {
    el.addEventListener("click", () => el.classList.toggle("expanded"));
  });
}

// escapeHtml : voir utils/export-builders.js

function updateBackendIndicator(status) {
  const dot   = document.getElementById("backendDot");
  const label = document.getElementById("backendLabel");
  if (status && status.available) {
    dot.className = "status-dot online";
    label.textContent = `Backend Python : actif (v${status.version ?? "?"})`;
  } else {
    dot.className = "status-dot offline";
    label.textContent = "Backend Python : non disponible";
  }
}

// =====================================================
// EXPORT — via chrome.downloads API (fiable depuis popup). Les builders
// (CSV/XML/SARIF/HTML) et les helpers (download, impression) viennent de
// utils/export-builders.js, partagés avec panel.js (Round 7/8 avaient fait
// évoluer le panel — preuves requête/réponse, SARIF, résumé exécutif,
// sparkline, remédiation — sans jamais reporter ces apports ici).
// =====================================================

async function doExport(format) {
  // Si pas de vulns en mémoire, on tente de charger depuis l'historique
  let data = vulns;
  if (!data || data.length === 0) {
    try {
      const { scanHistory } = await chrome.storage.local.get("scanHistory");
      if (scanHistory && scanHistory.length > 0) {
        data = scanHistory[0].vulnerabilities || [];
      }
    } catch (e) {}
  }
  if (!data || data.length === 0) {
    alert("Aucune vulnérabilité à exporter. Lancez d'abord un scan.");
    return;
  }

  // Exclut les faux positifs (triagés depuis le panel DevTools — la popup n'a
  // pas de boutons de triage ni de place dans son footer pour une case à
  // cocher "Inclure les faux positifs" comme le panel ; voir Round 8 Task 1).
  const vulnsToExport = data.filter(v => v.triageStatus !== "false_positive");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const scan = {
    id: currentScanId || crypto.randomUUID(),
    url: tab?.url || "",
    startedAt: data[0]?.detectedAt || Date.now(),
    finishedAt: Date.now(),
    vulnerabilities: vulnsToExport,
  };

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  const baseName = `vulnscan-${stamp}`;

  try {
    if (format === "json") {
      downloadBlob(JSON.stringify(scan, null, 2), `${baseName}.json`, "application/json");
    } else if (format === "csv") {
      downloadBlob(buildCSV(scan), `${baseName}.csv`, "text/csv;charset=utf-8");
    } else if (format === "html") {
      const priorScan = await fetchPriorScanForSummary(scan.url, scan.id, scan.startedAt);
      const trendPoints = await fetchRiskTrend(scan.url);
      downloadBlob(buildHTMLReport(scan, false, priorScan, trendPoints), `${baseName}.html`, "text/html;charset=utf-8");
    } else if (format === "xml") {
      downloadBlob(buildXML(scan), `${baseName}.xml`, "application/xml");
    } else if (format === "sarif") {
      downloadBlob(buildSARIF(scan), `${baseName}.sarif`, "application/sarif+json");
    } else if (format === "pdf") {
      // PDF = ouvre HTML imprimable dans un nouvel onglet, puis ferme la popup
      // (comportement historique de la popup — openPrintTab lui-même ne ferme
      // rien, il ne fait qu'ouvrir l'onglet).
      const priorScan = await fetchPriorScanForSummary(scan.url, scan.id, scan.startedAt);
      const trendPoints = await fetchRiskTrend(scan.url);
      openPrintTab(buildHTMLReport(scan, true, priorScan, trendPoints));
      window.close();
      return;
    }
  } catch (e) {
    console.error("[VulnScan popup] Export error:", e);
    alert("Erreur lors de l'export : " + e.message);
  }
}
