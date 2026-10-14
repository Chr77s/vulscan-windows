// ================================================================
//  taxonomy.js — Référentiel OWASP / CWE / CVSS / Liens
//  Pour enrichir automatiquement chaque finding selon son `type`.
// ================================================================
//
//  Sources :
//    - OWASP Top 10 2021 : https://owasp.org/Top10/
//    - CWE              : https://cwe.mitre.org/
//    - CVSS v3.1        : https://www.first.org/cvss/v3.1/
//    - OWASP ASVS       : https://owasp.org/www-project-application-security-verification-standard/
//
//  Le champ `cvssBase` est une valeur typique pour la classe de vuln.
//  Le score réel doit être recalculé selon le contexte (AV, AC, PR, UI, S, C, I, A).
// ================================================================

export const TAXONOMY = {
  "xss": {
    title: "Cross-Site Scripting",
    owasp: { id: "A03:2021", name: "Injection",
             url: "https://owasp.org/Top10/A03_2021-Injection/" },
    cwe:   { id: "CWE-79", name: "Improper Neutralization of Input During Web Page Generation",
             url: "https://cwe.mitre.org/data/definitions/79.html" },
    cvssBase: 6.1,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    impact: "Vol de session, défiguration, hameçonnage, exécution de code arbitraire dans le navigateur de la victime.",
    references: [
      { label: "OWASP XSS Prevention Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
      { label: "PortSwigger XSS", url: "https://portswigger.net/web-security/cross-site-scripting" },
    ],
  },

  "sqli": {
    title: "SQL Injection",
    owasp: { id: "A03:2021", name: "Injection",
             url: "https://owasp.org/Top10/A03_2021-Injection/" },
    cwe:   { id: "CWE-89", name: "SQL Injection",
             url: "https://cwe.mitre.org/data/definitions/89.html" },
    cvssBase: 9.8,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    impact: "Compromission totale de la base : lecture/écriture/destruction, exfiltration de données sensibles, escalade éventuelle vers RCE.",
    references: [
      { label: "OWASP SQLi Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
      { label: "PortSwigger SQLi", url: "https://portswigger.net/web-security/sql-injection" },
    ],
  },

  "ssti": {
    title: "Server-Side Template Injection",
    owasp: { id: "A03:2021", name: "Injection",
             url: "https://owasp.org/Top10/A03_2021-Injection/" },
    cwe:   { id: "CWE-1336", name: "Improper Neutralization of Special Elements Used in a Template Engine",
             url: "https://cwe.mitre.org/data/definitions/1336.html" },
    cvssBase: 9.8,
    impact: "Exécution de code arbitraire côté serveur dans la plupart des cas — équivalent fonctionnel d'un RCE.",
    references: [
      { label: "PortSwigger SSTI", url: "https://portswigger.net/web-security/server-side-template-injection" },
    ],
  },

  "csrf": {
    title: "Cross-Site Request Forgery",
    owasp: { id: "A01:2021", name: "Broken Access Control",
             url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
    cwe:   { id: "CWE-352", name: "Cross-Site Request Forgery",
             url: "https://cwe.mitre.org/data/definitions/352.html" },
    cvssBase: 6.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N",
    impact: "Exécution d'actions privilégiées (modif profil, virement, suppression) au nom d'une victime authentifiée.",
    references: [
      { label: "OWASP CSRF Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html" },
    ],
  },

  "outdated-library": {
    title: "Vulnerable & Outdated Components",
    owasp: { id: "A06:2021", name: "Vulnerable and Outdated Components",
             url: "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/" },
    cwe:   { id: "CWE-1104", name: "Use of Unmaintained Third Party Components",
             url: "https://cwe.mitre.org/data/definitions/1104.html" },
    cvssBase: 7.5,
    impact: "Exploitation de CVE publiques connues. Risque dépendant de la nature de la lib (XSS, RCE, DoS).",
    references: [
      { label: "Snyk Vuln DB", url: "https://security.snyk.io/" },
      { label: "NVD", url: "https://nvd.nist.gov/" },
    ],
  },

  "sensitive-data": {
    title: "Sensitive Data Exposure",
    owasp: { id: "A02:2021", name: "Cryptographic Failures",
             url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
    cwe:   { id: "CWE-200", name: "Exposure of Sensitive Information",
             url: "https://cwe.mitre.org/data/definitions/200.html" },
    cvssBase: 7.5,
    impact: "Fuite de secrets (clés API, JWT, mots de passe) → compromission de comptes, accès non autorisé à des systèmes tiers.",
    references: [
      { label: "OWASP Secrets Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html" },
    ],
  },

  "missing-header": {
    title: "Security Misconfiguration (Missing HTTP Header)",
    owasp: { id: "A05:2021", name: "Security Misconfiguration",
             url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
    cwe:   { id: "CWE-693", name: "Protection Mechanism Failure",
             url: "https://cwe.mitre.org/data/definitions/693.html" },
    cvssBase: 5.3,
    impact: "Surface d'attaque élargie (clickjacking, downgrade HTTPS, MIME sniffing, fuite Referer).",
    references: [
      { label: "OWASP Secure Headers Project", url: "https://owasp.org/www-project-secure-headers/" },
    ],
  },

  "weak-csp": {
    title: "Weak Content-Security-Policy",
    owasp: { id: "A05:2021", name: "Security Misconfiguration",
             url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
    cwe:   { id: "CWE-1021", name: "Improper Restriction of Rendered UI Layers",
             url: "https://cwe.mitre.org/data/definitions/1021.html" },
    cvssBase: 5.4,
    impact: "CSP contourne­able : les protections XSS sont diminuées.",
    references: [
      { label: "OWASP CSP Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html" },
    ],
  },

  "info-disclosure": {
    title: "Information Disclosure",
    owasp: { id: "A05:2021", name: "Security Misconfiguration",
             url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
    cwe:   { id: "CWE-200", name: "Information Exposure",
             url: "https://cwe.mitre.org/data/definitions/200.html" },
    cvssBase: 3.7,
    impact: "Empreinte technologique facilite la recherche d'exploits ciblés.",
    references: [],
  },

  "mixed-content": {
    title: "Mixed Content",
    owasp: { id: "A02:2021", name: "Cryptographic Failures",
             url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
    cwe:   { id: "CWE-311", name: "Missing Encryption of Sensitive Data",
             url: "https://cwe.mitre.org/data/definitions/311.html" },
    cvssBase: 4.8,
    impact: "Interception possible de ressources sur réseau hostile (MITM).",
    references: [],
  },

  "open-redirect": {
    title: "Open Redirect",
    owasp: { id: "A01:2021", name: "Broken Access Control",
             url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/" },
    cwe:   { id: "CWE-601", name: "URL Redirection to Untrusted Site",
             url: "https://cwe.mitre.org/data/definitions/601.html" },
    cvssBase: 6.1,
    impact: "Phishing crédible : l'URL légitime est utilisée pour rediriger vers un site malveillant.",
    references: [
      { label: "OWASP Unvalidated Redirects", url: "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards_Cheat_Sheet" },
    ],
  },

  "missing-sri": {
    title: "Missing Subresource Integrity",
    owasp: { id: "A08:2021", name: "Software & Data Integrity Failures",
             url: "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/" },
    cwe:   { id: "CWE-353", name: "Missing Support for Integrity Check",
             url: "https://cwe.mitre.org/data/definitions/353.html" },
    cvssBase: 5.4,
    impact: "Si un CDN est compromis, le code malveillant s'exécute en tant que script de confiance.",
    references: [
      { label: "MDN Subresource Integrity", url: "https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity" },
    ],
  },

  "insecure-cookie": {
    title: "Insecure Cookie Configuration",
    owasp: { id: "A05:2021", name: "Security Misconfiguration",
             url: "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/" },
    cwe:   { id: "CWE-1004", name: "Sensitive Cookie Without HttpOnly Flag",
             url: "https://cwe.mitre.org/data/definitions/1004.html" },
    cvssBase: 5.4,
    impact: "Cookie de session vol­able via XSS, interceptable sur HTTP, attaquable cross-site.",
    references: [
      { label: "OWASP Session Management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
    ],
  },

  "tls": {
    title: "Transport Layer Security",
    owasp: { id: "A02:2021", name: "Cryptographic Failures",
             url: "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/" },
    cwe:   { id: "CWE-326", name: "Inadequate Encryption Strength",
             url: "https://cwe.mitre.org/data/definitions/326.html" },
    cvssBase: 7.4,
    impact: "Interception / déchiffrement / falsification du trafic.",
    references: [
      { label: "OWASP TLS Cheat Sheet", url: "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html" },
    ],
  },
};

// Sévérité dérivée du score CVSS de base (NVD scale)
export function severityFromCvss(score) {
  if (score >= 9.0)  return "critical";
  if (score >= 7.0)  return "high";
  if (score >= 4.0)  return "medium";
  if (score >  0.0)  return "low";
  return "info";
}

// Enrichit un finding avec la taxonomie correspondante
export function enrichFinding(v) {
  const tax = TAXONOMY[v.type];
  if (!tax) return v;
  return {
    ...v,
    title:       v.title       || tax.title,
    owasp:       v.owasp       || tax.owasp,
    cwe:         v.cwe         || tax.cwe,
    cvssBase:    v.cvssBase    ?? tax.cvssBase,
    cvssVector:  v.cvssVector  || tax.cvssVector,
    impact:      v.impact      || tax.impact,
    references:  v.references  || tax.references || [],
  };
}
