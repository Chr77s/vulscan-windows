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
