// Pure DOM XSS probe builder/runner. The payload's only effect is setting data-vulnscan-hit=<token> on <html>.
const SET = (t) => `document.documentElement.setAttribute('data-vulnscan-hit','${t}')`;

export const DOM_PAYLOAD_TEMPLATES = [
  { context: "html", template: `'"--></style></script><img src=x onerror="${SET("{T}")}">` },
  { context: "js-single", template: `';${SET("{T}")};//` },
  { context: "js-double", template: `";${SET("{T}")};//` },
  { context: "js-url", template: `javascript:${SET("{T}")}` },
];

const defaultToken = () => "vs" + Math.random().toString(36).slice(2, 12) + Date.now().toString(36);

export function buildDomProbes(url, { maxProbes = 16, makeToken = defaultToken } = {}) {
  const names = [...new Set(new URL(url).searchParams.keys()), "#hash"];
  const probes = [];
  for (const param of names) {
    for (const { context, template } of DOM_PAYLOAD_TEMPLATES) {
      if (probes.length >= maxProbes) return probes;
      const token = makeToken();
      const payload = template.replaceAll("{T}", token);
      const u = new URL(url);
      if (param === "#hash") u.hash = payload; // replaces any existing fragment
      else u.searchParams.set(param, payload); // other params keep their values
      probes.push({ param, context, token, payload, probeUrl: u.href });
    }
  }
  return probes;
}

export async function runDomProbes({ probes, check, now, budgetMs = 40000, isStopped = () => false }) {
  const start = now();
  const hits = [];
  const done = new Set(); // params already confirmed
  for (const probe of probes) {
    if (isStopped() || now() - start >= budgetMs) break;
    if (done.has(probe.param)) continue;
    let ok = false;
    try { ok = await check(probe); } catch { /* not confirmed */ }
    if (ok) { hits.push(probe); done.add(probe.param); }
  }
  return hits;
}

export function domFindingFromHit(hit, scannedUrl) {
  return {
    type: "xss",
    title: "DOM XSS confirmée — exécution observée",
    severity: "high",
    confidence: 95,
    detectionMethod: "dom-execution-confirmed",
    source: "extension:dom-xss",
    parameter: hit.param,
    payload: hit.payload,
    url: scannedUrl, // stable key for rescan diffs; the probe URL (random token) goes in evidence
    evidence: `Le payload a posé data-vulnscan-hit=${hit.token} sur <html> (contexte ${hit.context}) — URL de sonde : ${hit.probeUrl}`,
    description: "La valeur du paramètre atteint un puits DOM exécutable : le payload s'est exécuté dans un vrai onglet du navigateur (preuve observée, pas une simple réflexion).",
    recommendation: "Encoder la donnée selon le contexte du puits, utiliser textContent plutôt qu'innerHTML, éviter eval et document.write avec des données issues de l'URL, et déployer une Content-Security-Policy restrictive.",
    cwe: "CWE-79",
    owasp: "A03:2021",
  };
}
