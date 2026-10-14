// ================================================================
//  service-worker.js — Coeur de l'extension VulnScan (v1.1)
//  Le backend Python est REQUIS — il fournit :
//    - lecture des vrais en-têtes HTTP (impossible côté browser)
//    - vérification CVE des bibliothèques
//    - corrélation bayésienne des signaux
// ================================================================

import { DEFAULT_CONFIG } from "../utils/constants.js";
import { enrichFinding } from "../utils/taxonomy.js";

// ---- État global ----
let currentScan = null;
let backendStatus = { available: false, lastChecked: 0, version: null, error: null };

// ---- Initialisation ----
chrome.runtime.onInstalled.addListener(async () => {
  console.log("[VulnScan] Extension installée / mise à jour");
  try {
    const { config } = await chrome.storage.local.get("config");
    if (!config) {
      await chrome.storage.local.set({ config: DEFAULT_CONFIG });
    }
    await chrome.alarms.create("backendHealthCheck", { periodInMinutes: 0.5 });
  } catch (err) {
    console.error("[VulnScan] Erreur init :", err);
  }
  await checkBackendHealth();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "backendHealthCheck") checkBackendHealth();
});

// =====================================================
// Backend health check
// =====================================================
async function checkBackendHealth() {
  const { config } = await chrome.storage.local.get("config");
  const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };
  const url = cfg.backendUrl + "/health";

  try {
    const r = await fetch(url, { signal: AbortSignal.timeout(3000) });
    if (r.ok) {
      const data = await r.json();
      backendStatus = {
        available: true,
        version: data.version,
        endpoints: data.endpoints,
        lastChecked: Date.now(),
        error: null,
      };
    } else {
      backendStatus = { available: false, lastChecked: Date.now(), error: "HTTP " + r.status };
    }
  } catch (e) {
    backendStatus = { available: false, lastChecked: Date.now(), error: e.message };
  }
  broadcastMessage({ type: "BACKEND_STATUS", payload: backendStatus });
  return backendStatus;
}

// =====================================================
// Message router
// =====================================================
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  handleMessage(message)
    .then(sendResponse)
    .catch((err) => {
      console.error("[VulnScan] Erreur message :", err);
      sendResponse({ error: err.message });
    });
  return true;
});

async function handleMessage(message) {
  switch (message.type) {
    case "START_SCAN":   return await startScan(message.payload.tabId, message.payload.url);
    case "STOP_SCAN":    return stopScan();
    case "GET_RESULTS":  return (await chrome.storage.local.get("scanHistory")).scanHistory || [];
    case "GET_RESULTS_BACKEND": return await fetchHistoryFromBackend();
    case "GET_CONFIG":   return (await chrome.storage.local.get("config")).config || DEFAULT_CONFIG;
    case "SET_CONFIG":
      await chrome.storage.local.set({ config: message.payload });
      return { success: true };
    case "BACKEND_STATUS":         return backendStatus;
    case "RECHECK_BACKEND":        return await checkBackendHealth();
    case "VULN_FOUND":
      // Relais en cours de scan : on ajoute au scan courant
      if (currentScan) {
        currentScan.vulnerabilities.push(message.payload);
        broadcastMessage({ type: "VULN_FOUND", payload: message.payload });
      }
      return { success: true };
    case "EXPORT_REPORT": {
      const { scanId } = message.payload || {};
      const { scanHistory } = await chrome.storage.local.get("scanHistory");
      const history = scanHistory || [];
      const scan = history.find(s => s.id === scanId) || history[0] || null;
      return { success: !!scan, scan };
    }
    case "SET_TRIAGE": {
      const { scanId, findingId, status, note } = message.payload || {};
      const { config } = await chrome.storage.local.get("config");
      const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };
      try {
        const r = await fetch(`${cfg.backendUrl}/history/triage/${findingId}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ status, note }),
          signal: AbortSignal.timeout(5000),
        });
        if (!r.ok) return { success: false, error: "HTTP " + r.status };
      } catch (e) {
        return { success: false, error: e.message };
      }
      const { scanHistory } = await chrome.storage.local.get("scanHistory");
      const history = scanHistory || [];
      const scan = history.find(s => s.id === scanId);
      const finding = scan && scan.vulnerabilities.find(v => v.id === findingId);
      if (finding) {
        finding.triageStatus = status;
        finding.triageNote = note || "";
        await chrome.storage.local.set({ scanHistory: history });
      }
      return { success: true };
    }
    default:
      return { error: "Type de message inconnu : " + message.type };
  }
}

// =====================================================
// Lancement de scan — pipeline complet
// =====================================================
async function startScan(tabId, url) {
  const { config } = await chrome.storage.local.get("config");
  const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };

  // 1. Vérifier que le backend est disponible — REQUIS
  await checkBackendHealth();
  if (!backendStatus.available) {
    const errMsg =
      "Le backend Python est requis mais ne répond pas (" +
      (backendStatus.error || "inconnu") +
      "). Lancez-le avec backend/start.bat puis réessayez.";
    broadcastMessage({ type: "SCAN_ERROR", payload: { error: errMsg } });
    return { error: errMsg };
  }

  // 2. Préparer le scan
  currentScan = {
    id: crypto.randomUUID(),
    url,
    startedAt: Date.now(),
    status: "running",
    vulnerabilities: [],
    scanMode: cfg.passiveEnabled && cfg.activeEnabled ? "both"
             : cfg.activeEnabled ? "active" : "passive",
    backendVersion: backendStatus.version,
  };

  console.log("[VulnScan] Scan démarré sur " + url + " (backend v" + backendStatus.version + ")");
  updateBadge("scanning");
  broadcastMessage({ type: "SCAN_PROGRESS", payload: { stage: "passive", label: "Analyse passive du DOM..." } });

  // 3. Phase A — analyse passive côté navigateur (content-script)
  let clientResult = { vulnerabilities: [], context: {} };
  try {
    clientResult = await runPassiveAnalysis(tabId, url, cfg);
  } catch (e) {
    console.warn("[VulnScan] Analyse passive échouée :", e.message);
  }

  // Enrichir et stocker les vulnérabilités client
  for (const raw of clientResult.vulnerabilities) {
    const v = ensureFinding(raw, url);
    if (!currentScan.vulnerabilities.find(x => x.id === v.id)) {
      currentScan.vulnerabilities.push(v);
      // Renvoyer la version enrichie au panel
      broadcastMessage({ type: "VULN_FOUND", payload: v });
    }
  }

  // 4. Phase B — augmentation backend (passive : headers, CVE, info-disclosure)
  broadcastMessage({ type: "SCAN_PROGRESS", payload: { stage: "backend", label: "Augmentation backend (en-têtes, CVE, corrélation)..." } });
  try {
    const backendVulns = await augmentViaBackend(cfg, url, clientResult);
    for (const v of backendVulns) {
      const enriched = ensureFinding(v, url);
      currentScan.vulnerabilities.push(enriched);
      broadcastMessage({ type: "VULN_FOUND", payload: enriched });
    }
    console.log("[VulnScan] Backend augment : " + backendVulns.length + " findings");
  } catch (e) {
    console.warn("[VulnScan] Augmentation backend échouée :", e.message);
  }

  // 5. Phase C — TESTS ACTIFS (sqli, xss, lfi, ssrf, etc.) si activés
  if (cfg.activeEnabled) {
    broadcastMessage({ type: "SCAN_PROGRESS", payload: { stage: "active", label: "Tests actifs (injections) en cours..." } });
    try {
      const { findings: activeVulns, discovery, moduleLog } = await runActiveModules(cfg, url);
      for (const v of activeVulns) {
        const enriched = ensureFinding(v, url);
        currentScan.vulnerabilities.push(enriched);
        broadcastMessage({ type: "VULN_FOUND", payload: enriched });
      }
      if (discovery) currentScan.discovery = discovery;
      if (moduleLog && moduleLog.length) broadcastMessage({ type: "MODULE_LOG", payload: moduleLog });
      console.log("[VulnScan] Tests actifs : " + activeVulns.length + " findings");
    } catch (e) {
      console.warn("[VulnScan] Tests actifs échoués :", e.message);
    }
  } else {
    console.log("[VulnScan] Tests actifs désactivés (activeEnabled = false)");
  }

  // 6. Finalisation
  return finalizeScan();
}

// =====================================================
// Phase C — Tests actifs via moteur modulaire backend
// =====================================================
// Construit l'objet d'auth depuis la config user — null si rien fourni
function buildAuthFromConfig(cfg) {
  const auth = {};

  // Parser les cookies sous forme "k1=v1; k2=v2"
  if (cfg.authCookies && cfg.authCookies.trim()) {
    const cookies = {};
    cfg.authCookies.split(";").forEach(pair => {
      const idx = pair.indexOf("=");
      if (idx > 0) {
        const k = pair.slice(0, idx).trim();
        const v = pair.slice(idx + 1).trim();
        if (k) cookies[k] = v;
      }
    });
    if (Object.keys(cookies).length > 0) auth.cookies = cookies;
  }

  // Headers
  const headers = {};
  if (cfg.authBearer && cfg.authBearer.trim()) {
    let val = cfg.authBearer.trim();
    if (!/^(bearer|basic|token)\s/i.test(val)) val = "Bearer " + val;
    headers["Authorization"] = val;
  }
  if (cfg.authHeaderName && cfg.authHeaderValue) {
    headers[cfg.authHeaderName.trim()] = cfg.authHeaderValue.trim();
  }
  if (Object.keys(headers).length > 0) auth.headers = headers;

  return Object.keys(auth).length > 0 ? auth : null;
}

// =====================================================
// Mapping profile → liste de modules
// =====================================================
const SCAN_PROFILES = {
  quick: [
    // Passive uniquement — modules qui ne tirent pas de payloads
    "headers", "info-disclosure", "tech-fingerprint", "cors-misconfig",
    "jwt-analysis", "waf-detect",
  ],
  standard: [
    // Couverture équilibrée : passive + actifs majeurs
    "headers", "info-disclosure", "tech-fingerprint", "cors-misconfig",
    "jwt-analysis", "waf-detect",
    "sqli", "xss", "lfi", "open-redirect", "idor", "ssrf", "xxe", "ssti", "nosqli",
    "file-exposure", "form-fuzzer", "header-injection",
  ],
  deep: [
    // TOUS les modules — long mais exhaustif
    "headers", "info-disclosure", "tech-fingerprint", "cors-misconfig",
    "jwt-analysis", "waf-detect",
    "sqli", "xss", "lfi", "command-injection", "open-redirect", "idor",
    "ssrf", "xxe", "ssti", "nosqli",
    "file-exposure", "dir-bruteforce", "rate-limit",
    "form-fuzzer", "header-injection", "param-discovery", "json-fuzzer",
    "ssl-tls", "graphql", "race-conditions", "subdomain-enum",
  ],
  owasp: [
    // Focalisé OWASP Top 10
    "sqli", "xss", "csrf", "lfi", "command-injection", "open-redirect", "idor",
    "ssrf", "xxe", "ssti", "nosqli", "jwt-analysis", "headers", "info-disclosure", "ssl-tls",
    "form-fuzzer",
  ],
  api: [
    // Focus API REST/GraphQL
    "tech-fingerprint", "jwt-analysis", "cors-misconfig", "rate-limit",
    "json-fuzzer", "graphql", "header-injection", "param-discovery",
    "info-disclosure", "nosqli",
  ],
};

async function runActiveModules(cfg, url) {
  let enabled = [];

  // Si profile sélectionné (sauf custom), on utilise le preset
  const profile = cfg.scanProfile || "standard";
  if (profile !== "custom" && SCAN_PROFILES[profile]) {
    enabled = [...SCAN_PROFILES[profile]];
  } else {
    // Custom : on prend les modules selon les cases cochées
    const CONFIG_TO_MODULES = {
      testSQLi:          "sqli",
      testXSS:           "xss",
      testPathTraversal: "lfi",
      testCmdInjection:  "command-injection",
      testOpenRedirect:  "open-redirect",
    };
    for (const [key, moduleName] of Object.entries(CONFIG_TO_MODULES)) {
      if (cfg[key]) enabled.push(moduleName);
    }
    enabled.push("idor", "ssrf", "xxe", "cors-misconfig", "jwt-analysis",
                 "tech-fingerprint", "file-exposure", "dir-bruteforce",
                 "form-fuzzer", "header-injection", "param-discovery", "json-fuzzer",
                 "ssl-tls", "graphql", "waf-detect");
  }

  if (enabled.length === 0) return { findings: [], discovery: null, moduleLog: [] };

  // Construire l'auth context depuis la config
  const auth = buildAuthFromConfig(cfg);
  console.log("[VulnScan] Modules actifs lancés :", enabled, "(auth:", auth ? "oui" : "non", ")");

  try {
    const r = await fetch(cfg.backendUrl + "/scanner/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: url,
        enabled,
        context: { ...(auth ? { auth } : {}), rate_limit_per_sec: cfg.requestsPerSecond },
      }),
      signal: AbortSignal.timeout(60000),  // 60s — les tests actifs peuvent être longs
    });
    if (!r.ok) {
      console.warn("[VulnScan] /scanner/run HTTP " + r.status);
      return { findings: [], discovery: null, moduleLog: [] };
    }
    const data = await r.json();
    return { findings: data.findings || [], discovery: data.discovery || null, moduleLog: data.moduleLog || [] };
  } catch (e) {
    console.warn("[VulnScan] /scanner/run KO :", e.message);
    return { findings: [], discovery: null, moduleLog: [] };
  }
}

// =====================================================
// Phase A — analyse passive côté navigateur
// =====================================================
async function runPassiveAnalysis(tabId, url, cfg) {
  let resp;
  try {
    resp = await chrome.tabs.sendMessage(tabId, {
      type: "START_PASSIVE_SCAN",
      payload: { url, config: cfg },
    });
  } catch {
    // Content-script pas encore injecté — on l'injecte
    try {
      await chrome.scripting.executeScript({
        target: { tabId },
        files: ["src/content/content-script.js"],
      });
      resp = await chrome.tabs.sendMessage(tabId, {
        type: "START_PASSIVE_SCAN",
        payload: { url, config: cfg },
      });
    } catch (err) {
      console.warn("[VulnScan] Impossible d'injecter content-script :", err.message);
      return { vulnerabilities: [], context: {} };
    }
  }
  return resp || { vulnerabilities: [], context: {} };
}

// =====================================================
// Phase B — augmentation côté backend Python
// =====================================================
async function augmentViaBackend(cfg, url, clientResult) {
  const allFindings = [];

  // B.1 — Récupérer les vrais en-têtes HTTP côté serveur
  try {
    const r = await fetch(cfg.backendUrl + "/analysis/fetch-headers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(10000),
    });
    if (r.ok) {
      const data = await r.json();
      (data.findings || []).forEach(f => allFindings.push(ensureFinding(f, url)));
    }
  } catch (e) {
    console.warn("[VulnScan] fetch-headers KO :", e.message);
  }

  // B.2 — Vérifier les bibliothèques contre la base CVE
  const libs = clientResult.context?.libraries || [];
  if (libs.length > 0) {
    try {
      const r = await fetch(cfg.backendUrl + "/analysis/cve-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ libraries: libs }),
        signal: AbortSignal.timeout(5000),
      });
      if (r.ok) {
        const data = await r.json();
        (data.findings || []).forEach(f => allFindings.push(ensureFinding(f, url)));
      }
    } catch (e) {
      console.warn("[VulnScan] cve-check KO :", e.message);
    }
  }

  // B.3 — Corrélation bayésienne : envoyer client + backend pour fusion
  try {
    const combinedInput = [
      ...(clientResult.vulnerabilities || []),
      ...allFindings,
    ];
    const r = await fetch(cfg.backendUrl + "/analysis/correlate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings: combinedInput }),
      signal: AbortSignal.timeout(5000),
    });
    if (r.ok) {
      const data = await r.json();
      // Le backend renvoie la liste corrélée et dédupliquée
      // → on garde uniquement les findings qui n'existent pas déjà côté client
      const clientIds = new Set((clientResult.vulnerabilities || []).map(v => v.id));
      const correlated = (data.findings || []).filter(f => !clientIds.has(f.id));
      return correlated.map(f => ensureFinding(f, url));
    }
  } catch (e) {
    console.warn("[VulnScan] correlate KO :", e.message);
  }

  // Fallback : retourner uniquement les findings backend bruts si correlate a échoué
  return allFindings;
}

function ensureFinding(f, url) {
  const base = {
    ...f,
    id: f.id || crypto.randomUUID(),
    detectedAt: f.detectedAt || Date.now(),
    scanMode: f.scanMode || "backend",
    severity: f.severity || "info",
    type: f.type || "unknown",
    url: f.url || url,
    description: f.description || "",
    recommendation: f.recommendation || "",
    parameter: f.parameter || "",
    evidence: f.evidence || "",
    payload: f.payload || null,            // ← payload utilisé (si test actif)
    detectionMethod: f.detectionMethod || "passive-dom-analysis",
    confidence: f.confidence ?? 80,
    source: f.source || "backend",
  };
  return enrichFinding(base);
}

// =====================================================
// Finalisation
// =====================================================
function finalizeScan() {
  if (!currentScan) return { success: false };
  currentScan.status = "completed";
  currentScan.finishedAt = Date.now();
  saveScanToHistory(currentScan);
  updateBadge("idle");
  const result = currentScan;
  currentScan = null;
  broadcastMessage({ type: "SCAN_COMPLETED", payload: result });
  return result;
}

function stopScan() {
  return finalizeScan();
}

async function saveScanToHistory(scan) {
  try {
    const { config, scanHistory } = await chrome.storage.local.get(["config", "scanHistory"]);
    const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };
    const history = scanHistory || [];
    history.unshift(scan);
    const trimmed = history.slice(0, cfg.maxHistoryItems);
    await chrome.storage.local.set({ scanHistory: trimmed });

    // Push asynchrone vers SQLite backend — best-effort
    pushScanToBackend(scan).catch(e => console.warn("[VulnScan] Backend history KO:", e.message));
  } catch (err) {
    console.error("[VulnScan] Erreur sauvegarde :", err);
  }
}

async function fetchHistoryFromBackend() {
  const { config } = await chrome.storage.local.get("config");
  const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };
  if (!cfg.useBackend || !backendStatus.available) return { scans: [], offline: true };
  try {
    const r = await fetch(cfg.backendUrl + "/history/list?limit=100", { signal: AbortSignal.timeout(5000) });
    if (!r.ok) return { scans: [], error: "HTTP " + r.status };
    return await r.json();
  } catch (e) {
    return { scans: [], error: e.message };
  }
}

async function pushScanToBackend(scan) {
  const { config } = await chrome.storage.local.get("config");
  const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };
  if (!cfg.useBackend || !backendStatus.available) return;
  await fetch(cfg.backendUrl + "/history/save", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(scan),
    signal: AbortSignal.timeout(5000),
  });
}

// =====================================================
// Badge / broadcast
// =====================================================
function updateBadge(state, count) {
  try {
    if (state === "critical" && count !== undefined) {
      chrome.action.setBadgeBackgroundColor({ color: "#CC0000" });
      chrome.action.setBadgeText({ text: String(count) });
    } else if (state === "scanning") {
      chrome.action.setBadgeBackgroundColor({ color: "#F59E0B" });
      chrome.action.setBadgeText({ text: "..." });
    } else {
      chrome.action.setBadgeText({ text: "" });
    }
  } catch (e) {}
}

function broadcastMessage(message) {
  chrome.runtime.sendMessage(message).catch(() => {});
}
