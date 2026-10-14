// ================================================================
//  popup.js — Logique de la popup VulnScan
//  Note : pas de "type=module" ici, script classique
// ================================================================

let isScanning = false;
let currentScanId = null;
let vulns = [];

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

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

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

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
// EXPORT — via chrome.downloads API (fiable depuis popup)
// =====================================================

const TYPE_LABEL_POPUP = {
  "xss": "Cross-Site Scripting", "sqli": "SQL Injection",
  "csrf": "Cross-Site Request Forgery", "outdated-library": "Vulnerable Component",
  "sensitive-data": "Sensitive Data", "missing-header": "Missing Header",
  "weak-csp": "Weak CSP", "info-disclosure": "Info Disclosure",
  "mixed-content": "Mixed Content", "open-redirect": "Open Redirect",
  "missing-sri": "Missing SRI", "insecure-cookie": "Insecure Cookie",
  "tls": "TLS/SSL", "path-traversal": "Path Traversal",
  "command-injection": "Command Injection", "ssrf": "SSRF", "xxe": "XXE",
  "idor": "IDOR", "jwt-weak": "Weak JWT", "cors-misconfig": "CORS Misconfig",
};
const SEV_LABEL_POPUP = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

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

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const scan = {
    id: currentScanId || crypto.randomUUID(),
    url: tab?.url || "",
    startedAt: data[0]?.detectedAt || Date.now(),
    finishedAt: Date.now(),
    vulnerabilities: data,
  };

  const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-");
  const baseName = `vulnscan-${stamp}`;
  let content, filename, mimeType;

  try {
    if (format === "json") {
      content = JSON.stringify(scan, null, 2);
      filename = `${baseName}.json`; mimeType = "application/json";
    } else if (format === "csv") {
      content = buildCsvPopup(scan);
      filename = `${baseName}.csv`; mimeType = "text/csv;charset=utf-8";
    } else if (format === "html") {
      content = buildHtmlReportPopup(scan, false);
      filename = `${baseName}.html`; mimeType = "text/html;charset=utf-8";
    } else if (format === "xml") {
      content = buildXmlPopup(scan);
      filename = `${baseName}.xml`; mimeType = "application/xml";
    } else if (format === "pdf") {
      // PDF = ouvre HTML imprimable dans un nouvel onglet
      const html = buildHtmlReportPopup(scan, true);
      const blob = new Blob([html], { type: "text/html" });
      const url = URL.createObjectURL(blob);
      await chrome.tabs.create({ url });
      window.close();
      return;
    }
    // Téléchargement via API native Chrome
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    await chrome.downloads.download({ url, filename, saveAs: false });
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch (e) {
    console.error("[VulnScan popup] Export error:", e);
    alert("Erreur lors de l'export : " + e.message);
  }
}

function buildCsvPopup(scan) {
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

function buildXmlPopup(scan) {
  const esc = (s) => String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&apos;");
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<vulnscan-report version="1.5">\n';
  xml += `  <metadata>\n    <scan-id>${esc(scan.id)}</scan-id>\n    <url>${esc(scan.url)}</url>\n`;
  xml += `    <started-at>${new Date(scan.startedAt).toISOString()}</started-at>\n`;
  xml += `    <total>${scan.vulnerabilities.length}</total>\n  </metadata>\n  <findings>\n`;
  for (const v of scan.vulnerabilities) {
    xml += `    <finding id="${esc(v.id)}" severity="${esc(v.severity)}" cvss="${v.cvssBase ?? ""}" confidence="${v.confidence ?? ""}">\n`;
    xml += `      <type>${esc(v.type)}</type>\n      <title>${esc(v.title || "")}</title>\n`;
    if (v.cwe) xml += `      <cwe id="${esc(v.cwe.id)}">${esc(v.cwe.name || "")}</cwe>\n`;
    if (v.owasp) xml += `      <owasp id="${esc(v.owasp.id)}">${esc(v.owasp.name || "")}</owasp>\n`;
    xml += `      <url>${esc(v.url)}</url>\n`;
    if (v.parameter) xml += `      <parameter>${esc(v.parameter)}</parameter>\n`;
    if (v.payload) xml += `      <payload><![CDATA[${v.payload}]]></payload>\n`;
    xml += `      <description>${esc(v.description)}</description>\n`;
    xml += `      <recommendation>${esc(v.recommendation)}</recommendation>\n`;
    if (v.evidence) xml += `      <evidence><![CDATA[${(v.evidence || "").slice(0, 1000)}]]></evidence>\n`;
    xml += `    </finding>\n`;
  }
  xml += `  </findings>\n</vulnscan-report>\n`;
  return xml;
}

function buildHtmlReportPopup(scan, forPrint) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const v of scan.vulnerabilities) if (v.severity in counts) counts[v.severity]++;
  const total = scan.vulnerabilities.length;
  const date = new Date(scan.startedAt).toLocaleString("fr-FR");

  const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const rows = scan.vulnerabilities.slice()
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 5) - (SEV_ORDER[b.severity] ?? 5))
    .map(v => `
      <tr class="sev-${v.severity}">
        <td><span class="badge badge-${v.severity}">${SEV_LABEL_POPUP[v.severity] || v.severity}</span></td>
        <td><strong>${escapeHtml(v.title || TYPE_LABEL_POPUP[v.type] || v.type)}</strong></td>
        <td>${v.cvssBase != null ? Number(v.cvssBase).toFixed(1) : "—"}</td>
        <td>${v.cwe ? `<a href="${v.cwe.url || '#'}">${v.cwe.id}</a>` : "—"}</td>
        <td>${v.owasp ? `<a href="${v.owasp.url || '#'}">${v.owasp.id}</a>` : "—"}</td>
        <td>${v.confidence != null ? v.confidence + "%" : "—"}</td>
        <td><code>${escapeHtml(v.url || "")}</code></td>
        <td>${escapeHtml(v.parameter || "—")}</td>
        <td>${escapeHtml(v.description || "")}</td>
        <td>${escapeHtml(v.recommendation || "")}</td>
        <td><pre>${escapeHtml((v.evidence || "").slice(0, 250))}</pre></td>
      </tr>`).join("");

  const autoPrint = forPrint
    ? `<script>window.addEventListener("load", () => setTimeout(() => window.print(), 300));<\/script>`
    : "";

  return `<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8"><title>VulnScan — Rapport</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;color:#1e293b;padding:30px;background:#fff}
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
@media print{body{padding:15px}.no-print{display:none}table{font-size:9.5px}pre{max-height:none}}
</style></head><body>
<header>
  <div style="font-size:36px">🛡️</div>
  <div>
    <h1>VulnScan — Rapport de sécurité</h1>
    <div class="meta"><strong>URL :</strong> <code>${escapeHtml(scan.url || "")}</code> · <strong>Date :</strong> ${date}</div>
  </div>
</header>
<h2>Résumé exécutif</h2>
<div class="summary">
  Scan automatisé de <strong>${escapeHtml(scan.url || "")}</strong> effectué le ${date}.
  <strong>${total}</strong> vulnérabilité(s) identifiée(s), dont <strong>${counts.critical}</strong> critique(s) et <strong>${counts.high}</strong> élevée(s).
</div>
<div class="kpis">
  <div class="kpi tot"><div class="v">${total}</div><div class="l">Total</div></div>
  <div class="kpi crit"><div class="v">${counts.critical}</div><div class="l">Critical</div></div>
  <div class="kpi high"><div class="v">${counts.high}</div><div class="l">High</div></div>
  <div class="kpi med"><div class="v">${counts.medium}</div><div class="l">Medium</div></div>
  <div class="kpi low"><div class="v">${counts.low}</div><div class="l">Low</div></div>
  <div class="kpi info"><div class="v">${counts.info}</div><div class="l">Info</div></div>
</div>
<h2>Détail des vulnérabilités</h2>
<table>
  <thead><tr><th>Sévérité</th><th>Titre</th><th>CVSS</th><th>CWE</th><th>OWASP</th><th>Conf.</th><th>URL</th><th>Paramètre</th><th>Description</th><th>Recommandation</th><th>Preuve</th></tr></thead>
  <tbody>${rows || '<tr><td colspan="11" style="text-align:center;color:#94a3b8;padding:20px">Aucune vulnérabilité</td></tr>'}</tbody>
</table>
<footer>
  Généré par VulnScan — Web Vulnerability Scanner · OWASP Top 10 / CWE / CVSS v3.1
  <br><button class="no-print" onclick="window.print()" style="margin-top:8px;padding:6px 14px;background:#4f46e5;color:white;border:none;border-radius:4px;cursor:pointer">🖨 Imprimer / Enregistrer en PDF</button>
</footer>
${autoPrint}
</body></html>`;
}
