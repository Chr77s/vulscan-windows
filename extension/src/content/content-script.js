// ================================================================
//  content-script.js — Analyse passive du DOM (v1.1)
//  Améliorations :
//    - Scoring de confiance (0-100%) multi-signaux
//    - Déduplication par signature
//    - Nouveaux détecteurs : clickjacking, mixed content,
//      open redirect, SRI manquant, DOM sinks, cookies non-sécurisés
//    - Patterns regex plus précis (moins de faux positifs)
// ================================================================

const DEFAULT_CONFIG = {
  passiveEnabled: true,
  testCSRF: true,
  testClickjacking: true,
  testMixedContent: true,
  testOpenRedirect: true,
  testCookies: true,
  testSRI: true,
  confidenceThreshold: 30,
};

// ---- Écoute des messages du Service Worker ----
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === "START_PASSIVE_SCAN") {
    const config = { ...DEFAULT_CONFIG, ...(message.payload.config ?? {}) };
    const results = runPassiveAnalysis(config);
    const context = collectContext();
    sendResponse({ vulnerabilities: results, context });
  }
  return true;
});

// ---- Collecte de contexte pour le backend ----
// Le backend a besoin de ces données pour :
//   - vérifier les versions de libs contre la base CVE
//   - corréler les signaux multi-pages
function collectContext() {
  const libraries = [];
  document.querySelectorAll("script[src]").forEach((s) => {
    const src = s.src || "";
    const m = src.match(/\/(?:([a-z][a-z\-]+?)[.\-])?(\d+\.\d+\.\d+)(?:\.min)?\.js/i);
    if (m && m[1]) {
      libraries.push({ name: m[1].toLowerCase(), version: m[2], url: src });
    }
  });

  return {
    libraries,
    formCount: document.querySelectorAll("form").length,
    scriptCount: document.querySelectorAll("script").length,
    pageTitle: document.title,
    pageLang: document.documentElement.lang || "",
    cookieCount: (document.cookie || "").split(";").filter(c => c.trim()).length,
  };
}

// ================================================================
// Pipeline d'analyse principal
// ================================================================
function runPassiveAnalysis(config) {
  const url = window.location.href;
  const isHttps = location.protocol === "https:";
  const findings = [];

  // Lancer tous les détecteurs
  findings.push(...analyzeDangerousPatterns(url));
  findings.push(...analyzeDomSinks(url));
  findings.push(...detectVulnerableLibraries(url));
  findings.push(...findSensitiveData(url));

  if (config.testCSRF)         findings.push(...analyzeFormsForCSRF(url));
  if (config.testMixedContent) findings.push(...analyzeMixedContent(url, isHttps));
  if (config.testOpenRedirect) findings.push(...analyzeOpenRedirects(url));
  if (config.testSRI)          findings.push(...analyzeMissingSRI(url));
  if (config.testCookies)      findings.push(...analyzeCookies(url));
  if (config.testClickjacking) findings.push(...analyzeClickjacking(url));

  // Déduplication + filtre seuil de confiance
  const minConf = Number(config.confidenceThreshold ?? 30);
  const unique = dedupe(findings).filter(v => (v.confidence ?? 100) >= minConf);

  // Tri par sévérité puis confiance
  const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  unique.sort((a, b) =>
    (ORDER[a.severity] - ORDER[b.severity]) || ((b.confidence ?? 0) - (a.confidence ?? 0))
  );

  // Note : c'est désormais le service-worker qui enrichit les findings
  // (taxonomy OWASP/CWE/CVSS) puis diffuse VULN_FOUND. On retourne juste la liste.
  return unique;
}

// ================================================================
// Helpers communs
// ================================================================
function makeVuln(params) {
  return {
    id: crypto.randomUUID(),
    detectedAt: Date.now(),
    scanMode: "passive",
    confidence: 80, // valeur par défaut
    ...params,
  };
}

function extractContext(code, keyword, before = 20, after = 80) {
  const idx = code.indexOf(keyword);
  if (idx === -1) return "";
  return code.slice(Math.max(0, idx - before), idx + after).replace(/\s+/g, " ").trim();
}

// Déduplique sur (type + parameter + premiers 60 chars de description)
function dedupe(arr) {
  const seen = new Map();
  for (const v of arr) {
    const key = `${v.type}|${v.parameter || ""}|${(v.description || "").slice(0, 60)}`;
    const existing = seen.get(key);
    if (!existing) seen.set(key, v);
    else if ((v.confidence ?? 0) > (existing.confidence ?? 0)) seen.set(key, v);
  }
  return Array.from(seen.values());
}

// ================================================================
// 1. Patterns JS dangereux (eval, document.write, innerHTML)
// ================================================================
function analyzeDangerousPatterns(url) {
  const out = [];
  const scripts = Array.from(document.querySelectorAll("script:not([src])"));

  for (const script of scripts) {
    const code = script.textContent || "";
    if (!code.trim()) continue;

    // eval()
    if (/\beval\s*\(/.test(code)) {
      // Confiance plus élevée si eval reçoit clairement une variable/concat
      const confidenceBoost = /eval\s*\(\s*[a-z_$]/i.test(code) || /eval\s*\(\s*["'`].*\+/.test(code) ? 95 : 75;
      out.push(makeVuln({
        type: "xss",
        severity: "high",
        url,
        description: "Utilisation de eval() détectée dans un script inline. Peut exécuter du code arbitraire si l'entrée est contrôlée par l'utilisateur.",
        recommendation: "Remplacer eval() par JSON.parse() pour les données, ou refactoriser pour éviter l'évaluation dynamique de chaînes.",
        evidence: extractContext(code, "eval("),
        confidence: confidenceBoost,
      }));
    }

    // document.write
    if (/document\.write(?:ln)?\s*\(/.test(code)) {
      const confBoost = /document\.write\s*\([^)]*\+/.test(code) ? 90 : 60;
      out.push(makeVuln({
        type: "xss",
        severity: "medium",
        url,
        description: "Utilisation de document.write() détectée. Comportement obsolète et vecteur XSS potentiel si la valeur est dynamique.",
        recommendation: "Utiliser createElement() + textContent, ou un framework moderne avec échappement automatique.",
        evidence: extractContext(code, "document.write"),
        confidence: confBoost,
      }));
    }

    // .innerHTML = qqch (non littéral)
    const innerHtmlMatches = code.match(/\.innerHTML\s*=\s*[^"'`;\n]/g);
    if (innerHtmlMatches) {
      out.push(makeVuln({
        type: "xss",
        severity: "high",
        url,
        description: "Assignation dynamique à innerHTML sans assainissement apparent. Risque XSS si la valeur provient d'une entrée utilisateur.",
        recommendation: "Utiliser textContent pour du texte simple, ou DOMPurify.sanitize() avant d'injecter du HTML.",
        evidence: extractContext(code, ".innerHTML"),
        confidence: 85,
      }));
    }

    // Function constructor — équivalent à eval
    if (/\bnew\s+Function\s*\(/.test(code)) {
      out.push(makeVuln({
        type: "xss",
        severity: "high",
        url,
        description: "Utilisation de new Function() détectée — équivalent à eval(). Vecteur d'exécution de code arbitraire.",
        recommendation: "Éviter la création dynamique de fonctions à partir de chaînes. Utiliser des callbacks classiques.",
        evidence: extractContext(code, "new Function"),
        confidence: 90,
      }));
    }

    // setTimeout / setInterval avec une chaîne (équivalent eval)
    if (/set(?:Timeout|Interval)\s*\(\s*["'`]/.test(code)) {
      out.push(makeVuln({
        type: "xss",
        severity: "medium",
        url,
        description: "setTimeout/setInterval reçoit une chaîne — interprétée comme du code. Comportement similaire à eval().",
        recommendation: "Passer une fonction directement : setTimeout(() => {...}, 1000)",
        evidence: extractContext(code, "setTimeout") || extractContext(code, "setInterval"),
        confidence: 85,
      }));
    }
  }
  return out;
}

// ================================================================
// 2. DOM sinks (location.href = userInput, href javascript:, etc.)
// ================================================================
function analyzeDomSinks(url) {
  const out = [];

  // Liens javascript:
  const jsLinks = Array.from(document.querySelectorAll('a[href^="javascript:"]'));
  if (jsLinks.length > 0) {
    out.push(makeVuln({
      type: "xss",
      severity: "low",
      url,
      parameter: `${jsLinks.length} lien(s) javascript:`,
      description: "Liens avec href='javascript:...' détectés. Pratique déconseillée, vecteur XSS si la valeur est dynamique.",
      recommendation: "Remplacer par addEventListener('click', handler).",
      evidence: jsLinks[0].outerHTML.slice(0, 150),
      confidence: 70,
    }));
  }

  // iframes sans sandbox
  const unsafeIframes = Array.from(document.querySelectorAll("iframe:not([sandbox])"));
  if (unsafeIframes.length > 0) {
    out.push(makeVuln({
      type: "xss",
      severity: "low",
      url,
      parameter: `${unsafeIframes.length} iframe(s) sans sandbox`,
      description: "iframes intégrées sans attribut sandbox. Si la source devient malveillante, peut accéder à la page parent.",
      recommendation: 'Ajouter sandbox="allow-scripts allow-same-origin" (ou plus restrictif) aux iframes tierces.',
      evidence: unsafeIframes[0].outerHTML.slice(0, 200),
      confidence: 60,
    }));
  }

  // Inputs sans autocomplete=off sur mots de passe / cartes
  const sensitiveInputs = Array.from(document.querySelectorAll('input[type="password"]:not([autocomplete])'));
  if (sensitiveInputs.length > 0) {
    out.push(makeVuln({
      type: "sensitive-data",
      severity: "low",
      url,
      parameter: "input[type=password]",
      description: "Champ de mot de passe sans attribut autocomplete configuré explicitement.",
      recommendation: 'Ajouter autocomplete="new-password" (création) ou "current-password" (login).',
      evidence: sensitiveInputs[0].outerHTML.slice(0, 150),
      confidence: 50,
    }));
  }

  return out;
}

// ================================================================
// 3. Bibliothèques JS obsolètes
// ================================================================
const VULNERABLE_LIBS = {
  jQuery: {
    pattern: /jquery[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    isVulnerable: (v) => {
      const [maj, min] = v.split(".").map(Number);
      return maj < 3 || (maj === 3 && min < 5);
    },
    cve: "CVE-2020-11023 / CVE-2019-11358 (XSS et prototype pollution)",
  },
  Angular: {
    pattern: /angular[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    isVulnerable: (v) => {
      const [maj, min] = v.split(".").map(Number);
      return maj === 1 && min < 8;
    },
    cve: "CVE-2019-10768 (prototype pollution)",
  },
  Lodash: {
    pattern: /lodash[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    isVulnerable: (v) => {
      const [maj, min, patch] = v.split(".").map(Number);
      return maj < 4 || (maj === 4 && min < 17) || (maj === 4 && min === 17 && patch < 21);
    },
    cve: "CVE-2020-8203 (prototype pollution)",
  },
  Moment: {
    pattern: /moment[.\-](\d+\.\d+\.\d+)(?:\.min)?\.js/i,
    isVulnerable: (v) => {
      const [maj, min] = v.split(".").map(Number);
      return maj < 2 || (maj === 2 && min < 29);
    },
    cve: "CVE-2022-31129 (ReDoS)",
  },
};

function detectVulnerableLibraries(url) {
  const out = [];
  const scripts = Array.from(document.querySelectorAll("script[src]"));

  for (const script of scripts) {
    const src = script.src;
    for (const [libName, { pattern, isVulnerable, cve }] of Object.entries(VULNERABLE_LIBS)) {
      const m = src.match(pattern);
      if (m && isVulnerable(m[1])) {
        out.push(makeVuln({
          type: "outdated-library",
          severity: "high",
          url,
          parameter: src,
          description: `Bibliothèque ${libName} v${m[1]} vulnérable détectée. ${cve}`,
          recommendation: `Mettre à jour ${libName} vers la dernière version stable.`,
          evidence: src,
          confidence: 95,
        }));
      }
    }
  }
  return out;
}

// ================================================================
// 4. CSRF (forms POST sans token)
// ================================================================
function analyzeFormsForCSRF(url) {
  const out = [];
  const forms = Array.from(document.querySelectorAll("form"));

  for (const form of forms) {
    const method = (form.method || "GET").toUpperCase();
    if (method !== "POST") continue;

    // Skip si action externe (cross-origin avec credentials gérés ailleurs)
    const action = form.action || "";
    if (action.startsWith("https://www.google.com")) continue; // ex: recherche

    const inputs = Array.from(form.querySelectorAll("input"));
    const hasCSRFToken = inputs.some(input => {
      const name = (input.name || "").toLowerCase();
      return name.includes("csrf") || name.includes("token")
          || name === "authenticity_token" || name === "_token"
          || name === "__requestverificationtoken";
    });

    if (!hasCSRFToken) {
      // Confiance plus haute si le form contient des champs sensibles
      const sensitive = inputs.some(i => /password|email|account|profile/i.test(i.name || ""));
      out.push(makeVuln({
        type: "csrf",
        severity: sensitive ? "high" : "medium",
        url,
        parameter: `<form action="${action || '?'}" method="POST">`,
        description: "Formulaire POST sans token CSRF détecté. Un attaquant pourrait forger des requêtes au nom de l'utilisateur.",
        recommendation: "Ajouter un token CSRF unique par session (champ hidden ou en-tête X-CSRF-Token) et le vérifier côté serveur.",
        evidence: form.outerHTML.slice(0, 250),
        confidence: sensitive ? 90 : 75,
      }));
    }
  }
  return out;
}

// ================================================================
// 5. Mixed content (HTTPS chargeant HTTP)
// ================================================================
function analyzeMixedContent(url, isHttps) {
  if (!isHttps) return [];
  const out = [];
  const insecure = Array.from(document.querySelectorAll(
    'script[src^="http://"], link[href^="http://"], img[src^="http://"], iframe[src^="http://"]'
  ));

  if (insecure.length > 0) {
    out.push(makeVuln({
      type: "mixed-content",
      severity: "medium",
      url,
      parameter: `${insecure.length} ressource(s) HTTP sur page HTTPS`,
      description: "La page HTTPS charge des ressources via HTTP. Le navigateur les bloquera (active) ou affichera un avertissement (passive).",
      recommendation: "Servir toutes les ressources en HTTPS, ou utiliser des URLs protocol-relative (//cdn.example.com/...).",
      evidence: insecure.map(el => el.src || el.href).slice(0, 3).join("\n"),
      confidence: 95,
    }));
  }
  return out;
}

// ================================================================
// 6. Open Redirect (paramètres next=, url=, redirect=)
// ================================================================
function analyzeOpenRedirects(url) {
  const out = [];
  const u = new URL(url);
  const SUSPECT = ["next", "url", "redirect", "return", "returnurl", "redirect_uri", "callback", "continue"];

  for (const key of SUSPECT) {
    const val = u.searchParams.get(key);
    if (val && /^https?:\/\//i.test(val)) {
      out.push(makeVuln({
        type: "open-redirect",
        severity: "medium",
        url,
        parameter: `?${key}=${val.slice(0, 60)}...`,
        description: "Paramètre de redirection suspect détecté. Vérifier que le serveur valide une whitelist de destinations.",
        recommendation: "Côté serveur, valider la cible contre une liste d'URLs autorisées avant la redirection.",
        evidence: `${key}=${val}`,
        confidence: 60, // ne peut être confirmé que côté serveur
      }));
    }
  }
  return out;
}

// ================================================================
// 7. Subresource Integrity (SRI manquant sur CDN externes)
// ================================================================
function analyzeMissingSRI(url) {
  const out = [];
  const externals = Array.from(document.querySelectorAll("script[src], link[rel=stylesheet]"))
    .filter(el => {
      const src = el.src || el.href;
      if (!src) return false;
      try {
        const u = new URL(src, location.href);
        return u.origin !== location.origin && !el.integrity;
      } catch { return false; }
    });

  if (externals.length > 0) {
    out.push(makeVuln({
      type: "missing-sri",
      severity: "low",
      url,
      parameter: `${externals.length} ressource(s) externe(s) sans SRI`,
      description: "Ressources externes (CDN) chargées sans attribut integrity. Risque si le CDN est compromis.",
      recommendation: 'Ajouter integrity="sha384-..." et crossorigin="anonymous" aux scripts/CSS tiers.',
      evidence: externals.slice(0, 3).map(el => el.src || el.href).join("\n"),
      confidence: 100,
    }));
  }
  return out;
}

// ================================================================
// 8. Cookies non-sécurisés (lisibles via document.cookie)
// ================================================================
function analyzeCookies(url) {
  if (!document.cookie) return [];
  const out = [];
  const cookies = document.cookie.split(";").map(c => c.trim()).filter(Boolean);

  // Note : on ne peut pas lire les flags HttpOnly/Secure depuis JS (et c'est tant mieux).
  // Mais on peut détecter les cookies sensibles ACCESSIBLES en JS — ce qui est déjà une fuite.
  const sensitive = cookies.filter(c => /^(session|sess|sid|auth|token|jwt|csrftoken)/i.test(c));
  if (sensitive.length > 0) {
    out.push(makeVuln({
      type: "insecure-cookie",
      severity: "medium",
      url,
      parameter: sensitive.map(c => c.split("=")[0]).join(", "),
      description: "Cookie de session/auth accessible via document.cookie — donc sans flag HttpOnly. Vulnérable au vol via XSS.",
      recommendation: "Marquer le cookie côté serveur avec HttpOnly; Secure; SameSite=Strict (ou Lax).",
      evidence: sensitive[0].slice(0, 80),
      confidence: 85,
    }));
  }
  return out;
}

// ================================================================
// 9. Clickjacking (pas de protection visible)
// ================================================================
function analyzeClickjacking(url) {
  // On ne peut pas lire les headers HTTP depuis content-script.
  // Mais on peut détecter <meta http-equiv="X-Frame-Options">
  // et la présence d'une CSP frame-ancestors via meta http-equiv="Content-Security-Policy"
  const meta = document.querySelector('meta[http-equiv="X-Frame-Options" i]');
  const csp = document.querySelector('meta[http-equiv="Content-Security-Policy" i]');
  const cspHasFrameAncestors = csp && /frame-ancestors/i.test(csp.content || "");

  if (!meta && !cspHasFrameAncestors) {
    return [makeVuln({
      type: "missing-header",
      severity: "low",
      url,
      parameter: "X-Frame-Options / frame-ancestors",
      description: "Aucune protection anti-clickjacking visible dans le HTML (X-Frame-Options ou CSP frame-ancestors).",
      recommendation: "Configurer côté serveur : X-Frame-Options: DENY (ou SAMEORIGIN), ou CSP frame-ancestors 'self'.",
      confidence: 40, // faible car les headers HTTP peuvent exister sans qu'on les voie
    })];
  }
  return [];
}

// ================================================================
// 10. Données sensibles dans le HTML (clés API, emails, paths, stack traces)
// ================================================================
const SENSITIVE_PATTERNS = [
  {
    name: "Clé API potentielle",
    regex: /\b(api[_-]?key|secret[_-]?key|access[_-]?token|sk_live_|sk_test_|pk_live_)\s*[:=]\s*["']?[\w\-]{20,}/gi,
    severity: "critical",
    confidence: 90,
  },
  {
    name: "JWT exposé",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    severity: "high",
    confidence: 95,
  },
  {
    name: "Stack trace exposée",
    regex: /(?:Traceback \(most recent call last\)|Exception in thread|at\s+[\w.$]+\s+\([^)]*\.(java|js|py|rb):\d+)/g,
    severity: "high",
    confidence: 90,
  },
  {
    name: "Chemin absolu serveur",
    regex: /(?:\/var\/www\/|\/home\/[a-z]+\/|\/etc\/(?:passwd|shadow)|C:\\Users\\\w+\\)/g,
    severity: "medium",
    confidence: 80,
  },
  {
    name: "Connexion DB exposée",
    regex: /\b(?:postgres|mysql|mongodb|redis):\/\/[^\s'"<>]+/gi,
    severity: "critical",
    confidence: 95,
  },
  {
    name: "Adresse IP privée",
    regex: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b/g,
    severity: "low",
    confidence: 60,
  },
  {
    name: "Adresse email exposée",
    regex: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
    severity: "low",
    confidence: 70,
  },
];

function findSensitiveData(url) {
  const out = [];
  // Limiter au HTML brut (textes + scripts inline + commentaires)
  const html = document.documentElement.outerHTML;

  for (const { name, regex, severity, confidence } of SENSITIVE_PATTERNS) {
    regex.lastIndex = 0;
    const matches = new Set();
    let m;
    while ((m = regex.exec(html)) !== null && matches.size < 5) {
      matches.add(m[0]);
    }
    if (matches.size > 0) {
      const samples = Array.from(matches).slice(0, 3).map(s => s.slice(0, 80)).join("\n");
      out.push(makeVuln({
        type: "sensitive-data",
        severity,
        url,
        parameter: `${matches.size} occurrence(s)`,
        description: `${name} détecté${matches.size > 1 ? "es" : ""} dans le code source de la page.`,
        recommendation: "Ne jamais exposer d'informations sensibles dans le HTML public. Utiliser des variables d'environnement côté serveur.",
        evidence: samples,
        confidence,
      }));
    }
  }
  return out;
}
