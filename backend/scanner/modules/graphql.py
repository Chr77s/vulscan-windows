"""
Module : GraphQL Fuzzer.

Tests classiques pour endpoints GraphQL :
  1. Détection — URL contient /graphql ou /api/graphql
  2. Introspection activée — requête `{__schema{types{name}}}` accessible ?
     → Si oui : info disclosure (expose tout le schéma de l'API)
  3. Suggestion non-désactivée — détection via erreur 'Did you mean ...'
  4. Batch queries — DoS potentiel via array de queries
  5. Injection dans variables — payloads SQLi/XSS dans les variables typées

OWASP A03 / CWE-89, CWE-200.

Référence : https://github.com/dolevf/graphql-cop
"""
from __future__ import annotations
from typing import List, Dict, Any
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding


class GraphQLModule(ScannerModule):
    name = "graphql"
    category = "injection"
    title = "GraphQL Fuzzer"
    description = "Détecte les endpoints GraphQL et teste introspection, batching, injection variables."
    default_enabled = True

    # Indices de présence GraphQL
    URL_HINTS = ["/graphql", "/api/graphql", "/v1/graphql", "/v2/graphql",
                 "/query", "/api/query", "/gql", "/api/gql"]

    INTROSPECTION_QUERY = {
        "query": "{__schema{types{name}}}"
    }

    BATCH_QUERY = [
        {"query": "{__typename}"}, {"query": "{__typename}"},
        {"query": "{__typename}"}, {"query": "{__typename}"},
    ]

    SUGGESTION_QUERY = {
        "query": "{ userrr { id name } }"  # typo volontaire pour déclencher 'Did you mean'
    }

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        # Découvrir les endpoints GraphQL — target lui-même + endpoints du crawler
        endpoints = self._discover_endpoints(target, context)
        if not endpoints:
            return []

        findings: List[Finding] = []
        for ep in endpoints[:3]:
            findings.extend(self._test_endpoint(ep, context))
        return findings

    def _discover_endpoints(self, target: str, context: Dict[str, Any]) -> List[str]:
        candidates = set()
        # Target direct si URL contient un hint
        if any(h in target.lower() for h in self.URL_HINTS):
            candidates.add(target)
        # Endpoints découverts par le crawler
        crawled = (context.get("crawled") or {})
        for ep in crawled.get("api_endpoints", []):
            if any(h in ep.lower() for h in self.URL_HINTS):
                candidates.add(ep)
        # Tente aussi les chemins canoniques sur le host de target
        from urllib.parse import urlparse
        parsed = urlparse(target)
        if parsed.netloc:
            base = f"{parsed.scheme}://{parsed.netloc}"
            for h in ["/graphql", "/api/graphql"]:
                # On tente une probe légère
                try:
                    r = http.post(base + h, context, json={"query": "{__typename}"},
                                  timeout=5, headers={"User-Agent": "VulnScan/1.4"})
                    if r.status_code != 404 and ("data" in r.text or "errors" in r.text):
                        candidates.add(base + h)
                except Exception:
                    continue
        return sorted(candidates)

    def _test_endpoint(self, url: str, context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []

        # 1. Introspection
        try:
            r = http.post(url, context, json=self.INTROSPECTION_QUERY,
                          timeout=8, headers={"User-Agent": "VulnScan/1.4"})
            body = r.text
            if r.status_code == 200 and ("__schema" in body and "types" in body):
                findings.append(Finding(
                    type="graphql-introspection", severity="medium",
                    title="Introspection GraphQL activée",
                    description=(
                        "L'endpoint expose son schéma complet via introspection. "
                        "Tout attaquant peut cartographier la totalité de l'API."
                    ),
                    recommendation=(
                        "Désactiver l'introspection en production (depending on framework : "
                        "Apollo `introspection: false`, GraphQL-PHP, Hasura, etc.)."
                    ),
                    url=url, parameter="introspection",
                    payload=str(self.INTROSPECTION_QUERY),
                    evidence=body[:300].replace("\n", " "),
                    confidence=100, cwe_id="CWE-200", owasp_id="A05:2021",
                    cvss_base=5.3,
                    detection_method="introspection-query",
                    source="module:graphql",
                ))
        except Exception:
            pass

        # 2. Suggestion non désactivée ('Did you mean...')
        try:
            r = http.post(url, context, json=self.SUGGESTION_QUERY,
                          timeout=8, headers={"User-Agent": "VulnScan/1.4"})
            if "Did you mean" in r.text:
                findings.append(Finding(
                    type="graphql-suggestion", severity="low",
                    title="GraphQL : suggestions de champs activées",
                    description=(
                        "L'API renvoie des 'Did you mean ...' qui révèlent les noms de champs "
                        "même si l'introspection est désactivée."
                    ),
                    recommendation="Désactiver les suggestions ('Did you mean') côté serveur.",
                    url=url, parameter="suggestion",
                    payload=str(self.SUGGESTION_QUERY),
                    evidence=re.search(r"Did you mean[^\"]{0,100}", r.text).group(0)[:150],
                    confidence=95, cwe_id="CWE-200", owasp_id="A05:2021",
                    cvss_base=3.7,
                    detection_method="suggestion-trigger",
                    source="module:graphql",
                ))
        except Exception:
            pass

        # 3. Batching activé → DoS potentiel
        try:
            r = http.post(url, context, json=self.BATCH_QUERY,
                          timeout=8, headers={"User-Agent": "VulnScan/1.4"})
            if r.status_code == 200 and r.text.strip().startswith("[") and "__typename" in r.text:
                findings.append(Finding(
                    type="graphql-batch", severity="medium",
                    title="GraphQL : batch queries acceptées (DoS potentiel)",
                    description=(
                        "L'endpoint accepte un array de queries dans une seule requête. "
                        "Permet de contourner le rate-limiting et de monter en charge facilement."
                    ),
                    recommendation=(
                        "Limiter la profondeur et la complexité des queries (depth/cost analysis). "
                        "Désactiver le batching si non utilisé."
                    ),
                    url=url, parameter="batching",
                    payload=str(self.BATCH_QUERY)[:200],
                    evidence=r.text[:200],
                    confidence=90, cwe_id="CWE-770", owasp_id="A04:2021",
                    cvss_base=5.3,
                    detection_method="batch-request-test",
                    source="module:graphql",
                ))
        except Exception:
            pass

        # 4. SQLi via variable typée
        try:
            sqli_payload = {
                "query": "query($id: ID!) { user(id: $id) { name } }",
                "variables": {"id": "1' OR '1'='1"},
            }
            r = http.post(url, context, json=sqli_payload, timeout=8,
                          headers={"User-Agent": "VulnScan/1.4"})
            if re.search(r"sql syntax|sqlite|mysql|postgres|ora-\d", r.text, re.I):
                findings.append(Finding(
                    type="sqli", severity="critical",
                    title="GraphQL : SQLi via variable",
                    description="Erreur SQL exposée après injection dans une variable GraphQL.",
                    recommendation="Préparer les queries côté DB. Valider les types côté serveur.",
                    url=url, parameter="GraphQL variable $id",
                    payload=str(sqli_payload),
                    evidence=r.text[:200],
                    confidence=90, cwe_id="CWE-89", owasp_id="A03:2021",
                    cvss_base=9.8,
                    detection_method="graphql-variable-injection",
                    source="module:graphql",
                ))
        except Exception:
            pass

        return findings
