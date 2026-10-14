// ================================================================
//  export-builders.js — logique d'export partagée entre le panel DevTools
//  (panel.js) et la popup (popup.js). Script classique (pas de
//  type="module" : manifest V3 + CSP script-src 'self' chargent les pages
//  d'extension via <script src>, donc ces fonctions deviennent globales dès
//  que ce fichier est chargé avant panel.js / popup.js dans leur .html).
//  Round 7/8 avaient fait évoluer panel.js (SARIF, résumé exécutif,
//  sparkline, remédiation, preuves requête/réponse) sans jamais reporter
//  ces apports dans la copie indépendante de popup.js — ce fichier élimine
//  cette duplication en centralisant les deux jeux de fonctions.
// ================================================================

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
  "ssrf": "SSRF",
  "xxe": "XXE",
  "idor": "IDOR",
  "jwt-weak": "Weak JWT",
  "cors-misconfig": "CORS Misconfiguration",
};

function escapeHtml(str) {
  if (str == null) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

// Final fix wave (Fix 3) : un « ]]> » littéral dans un contenu capturé (cible
// scannée potentiellement hostile) fermerait la section CDATA avant l'heure et
// permettrait d'injecter de la structure XML — on le scinde en deux sections.
function cdataSafe(s) {
  return String(s ?? "").replace(/]]>/g, "]]]]><![CDATA[>");
}

// Round 7 follow-up (I1) : échappe ET valide le schéma avant de rendre un lien
// cliquable -- cwe.url/owasp.url viennent aujourd'hui uniquement de données
// fiables (taxonomy.js statique, ou cwe_id/owasp_id fixes par module), donc
// non exploitable actuellement, mais latent si un futur module dérive un jour
// ces champs depuis le contenu de la cible scannée. new URL() accepte déjà
// "javascript:alert(1)" comme URL valide (protocol: "javascript:") -- c'est
// justement ce que ce contrôle de schéma rejette.
function safeHref(url) {
  try {
    const u = new URL(url);
    return (u.protocol === "http:" || u.protocol === "https:") ? u.href : "#";
  } catch {
    return "#";
  }
}

function sarifLevelFor(severity) {
  return severity === "critical" || severity === "high" ? "error"
       : severity === "medium" ? "warning"
       : "note";
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
  return                   { label: "Risque critique", color: "var(--critical)" };
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

// Round 8, Task 4 : récupère le scan précédent de la même URL (s'il existe) pour
// alimenter le résumé exécutif data-driven du rapport HTML/PDF.
// Final fix wave (Fix 2) : le filtre `url` de /history/list est un LIKE '%url%'
// (sous-chaîne) — on ne s'y fie que comme pré-filtre et on garde côté client
// uniquement l'URL exactement égale ET strictement antérieure au scan exporté
// (sinon un scan de http://site.com/login, ou un scan plus récent quand on
// exporte un ancien scan rouvert depuis l'Historique, pouvait servir de
// « précédent »). limit=100 : la liste backend est triée du plus récent au plus
// ancien, la borne doit donc dépasser tous les scans plus récents de même
// sous-chaîne pour atteindre le précédent d'un ancien scan rouvert.
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

function downloadBlob(content, filename, mimeType) {
  // Utilise chrome.downloads.download — fiable depuis un DevTools panel ou une
  // popup (le truc <a download>.click() est souvent bloqué dans ces contextes).
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
  // Utilise chrome.tabs.create — fiable depuis un DevTools panel ou une popup
  // (window.open est souvent bloqué dans ces contextes).
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
        <td>${v.cvssBase != null ? Number(v.cvssBase).toFixed(1) : "—"}</td>
        <td>${v.cwe ? `<a href="${escapeHtml(safeHref(v.cwe.url))}">${escapeHtml(v.cwe.id)}</a>` : "—"}</td>
        <td>${v.owasp ? `<a href="${escapeHtml(safeHref(v.owasp.url))}">${escapeHtml(v.owasp.id)}</a>` : "—"}</td>
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
