// ================================================================
//  options.js — Logique de la page d'options (script externe pour CSP)
// ================================================================

const DEFAULT_CONFIG = {
  passiveEnabled: true,
  activeEnabled: false,
  testSQLi: true,
  testXSS: true,
  testPathTraversal: true,
  testCmdInjection: false,
  testCSRF: true,
  testClickjacking: true,
  testMixedContent: true,
  testOpenRedirect: true,
  testCookies: true,
  testSRI: true,
  requestsPerSecond: 10,
  maxHistoryItems: 50,
  confidenceThreshold: 30,
  useBackend: true, // Le backend est REQUIS en v1.1
  backendUrl: "http://localhost:9876",
  // Round 5 — Auth pour scan post-login
  authCookies: "",
  authBearer: "",
  authHeaderName: "",
  authHeaderValue: "",
  // Round 5 — Profile de scan
  scanProfile: "standard",
};

const CHECKBOX_FIELDS = [
  "passiveEnabled", "activeEnabled",
  "testSQLi", "testXSS", "testPathTraversal", "testCmdInjection", "testCSRF",
  "testClickjacking", "testMixedContent", "testOpenRedirect", "testCookies", "testSRI",
  "useBackend",
];

const NUMBER_FIELDS = ["requestsPerSecond", "maxHistoryItems", "confidenceThreshold"];
const TEXT_FIELDS   = ["backendUrl", "authCookies", "authBearer", "authHeaderName", "authHeaderValue", "scanProfile"];

document.addEventListener("DOMContentLoaded", async () => {
  await loadConfig();
  setupListeners();
  await testBackend();
});

async function loadConfig() {
  const { config } = await chrome.storage.local.get("config");
  const cfg = { ...DEFAULT_CONFIG, ...(config || {}) };

  for (const key of CHECKBOX_FIELDS) {
    const el = document.getElementById(key);
    if (el) el.checked = !!cfg[key];
  }
  for (const key of [...NUMBER_FIELDS, ...TEXT_FIELDS]) {
    const el = document.getElementById(key);
    if (el) el.value = cfg[key];
  }
}

function setupListeners() {
  document.getElementById("btnSave").addEventListener("click", saveConfig);
  document.getElementById("btnReset").addEventListener("click", resetConfig);
  document.getElementById("btnClose").addEventListener("click", () => window.close());
  document.getElementById("btnTestBackend").addEventListener("click", testBackend);
}

async function saveConfig() {
  const cfg = {};
  for (const key of CHECKBOX_FIELDS) {
    const el = document.getElementById(key);
    if (el) cfg[key] = !!el.checked;
  }
  for (const key of NUMBER_FIELDS) {
    const el = document.getElementById(key);
    if (el) cfg[key] = parseInt(el.value, 10) || DEFAULT_CONFIG[key];
  }
  for (const key of TEXT_FIELDS) {
    const el = document.getElementById(key);
    if (el) cfg[key] = (el.value || "").trim() || DEFAULT_CONFIG[key];
  }

  try {
    await chrome.storage.local.set({ config: cfg });
    // Notifier aussi le SW (au cas où il garde un cache)
    try { await chrome.runtime.sendMessage({ type: "SET_CONFIG", payload: cfg }); } catch {}
    showToast("success", "✓ Configuration sauvegardée");
  } catch (e) {
    showToast("error", "✗ Erreur : " + e.message);
  }
}

async function resetConfig() {
  if (!confirm("Restaurer les valeurs par défaut ?")) return;
  await chrome.storage.local.set({ config: DEFAULT_CONFIG });
  await loadConfig();
  showToast("success", "✓ Valeurs par défaut restaurées");
}

async function testBackend() {
  const url = (document.getElementById("backendUrl").value || "http://localhost:9876").trim();
  const dot = document.getElementById("backendDot");
  const lbl = document.getElementById("backendLabel");
  dot.className = "dot";
  lbl.textContent = "Test en cours...";

  try {
    const ctrl = new AbortController();
    const timeout = setTimeout(() => ctrl.abort(), 3000);
    const r = await fetch(url + "/health", { signal: ctrl.signal });
    clearTimeout(timeout);

    if (!r.ok) throw new Error("HTTP " + r.status);
    const data = await r.json();
    dot.className = "dot ok";
    lbl.textContent = `Backend actif (v${data.version || "?"}) — ${url}`;
  } catch (e) {
    dot.className = "dot ko";
    lbl.textContent = `Non disponible — ${e.message}. Lancez : python backend/app.py`;
  }
}

function showToast(kind, message) {
  const toast = document.getElementById("toast");
  toast.className = "toast " + kind;
  toast.textContent = message;
  toast.style.display = "inline-block";
  clearTimeout(showToast._t);
  showToast._t = setTimeout(() => { toast.style.display = "none"; }, 2800);
}
