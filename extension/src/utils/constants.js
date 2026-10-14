// ================================================================
//  constants.js — Configuration par defaut et constantes VulnScan
// ================================================================

export const DEFAULT_CONFIG = {
  passiveEnabled: true,
  activeEnabled: false,
  testSQLi: true,
  testXSS: true,
  testPathTraversal: true,
  testCmdInjection: false,
  testSSTI: false,
  testCSRF: true,
  // Nouveaux détecteurs v1.1
  testClickjacking: true,
  testMixedContent: true,
  testOpenRedirect: true,
  testCookies: true,
  testSRI: true,
  // Scoring
  confidenceThreshold: 30,
  // Général
  minSeverity: "low",
  requestsPerSecond: 10,
  // Round 7 — thème clair/sombre (Task 8). "dark" est la valeur par défaut ;
  // toute valeur différente de "light" est traitée comme sombre par panel.js.
  theme: "dark",
  // Round 7 — sélecteur fin de modules (remplace le profil "Custom" à 5 cases)
  // null/absent = jamais configuré -> comportement legacy (5 cases + liste fixe) ;
  // [] = configuré explicitement à zéro module -> aucun module actif.
  customModules: null,
  // Round 8 — exports : false = les findings marqués « Faux positif » sont exclus
  // de tous les formats d'export ; true = inclus.
  includeFalsePositivesInExport: false,
  excludedUrls: [],
  useBackend: true, // REQUIS depuis v1.1
  backendUrl: "http://localhost:9876",
  maxHistoryItems: 50,
};

export const SEVERITY_ORDER = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function makeVuln(params) {
  return {
    id: crypto.randomUUID(),
    detectedAt: Date.now(),
    scanMode: "passive",
    ...params,
  };
}
