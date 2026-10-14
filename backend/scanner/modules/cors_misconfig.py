"""
Module : CORS misconfiguration.

Envoie une requête avec Origin: https://evil.example.com et vérifie :
  - Access-Control-Allow-Origin reflète l'origine arbitraire (mauvais)
  - Access-Control-Allow-Origin: *  ET  Allow-Credentials: true (mauvais)
  - Allow-Origin: null (mauvais — null exploitable depuis sandbox iframe)

OWASP A05 / CWE-942.
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import re

from scanner.core.module_base import ScannerModule, Finding


class CorsMisconfigModule(ScannerModule):
    name = "cors-misconfig"
    category = "misconfiguration"
    title = "CORS Misconfiguration"
    description = "Détecte les politiques CORS trop permissives ou réfléchies."
    default_enabled = True

    EVIL_ORIGIN = "https://evil.vulnscan-canary.example.com"

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []

        # Test 1 : origin reflechie
        try:
            r = requests.get(target, timeout=8, headers={
                "User-Agent": "VulnScan/1.2",
                "Origin": self.EVIL_ORIGIN,
            })
        except Exception:
            return findings

        aco  = r.headers.get("Access-Control-Allow-Origin", "")
        acc  = r.headers.get("Access-Control-Allow-Credentials", "").lower()

        if aco == self.EVIL_ORIGIN:
            findings.append(Finding(
                type="cors-misconfig", severity="high",
                title="CORS : Origin reflétée sans validation",
                description=(
                    f"Le serveur renvoie Access-Control-Allow-Origin: {self.EVIL_ORIGIN} "
                    "en réponse à une requête avec Origin arbitraire. Toute page tierce peut "
                    "lire les réponses authentifiées."
                ),
                recommendation=(
                    "Maintenir une whitelist explicite d'origines autorisées. Ne jamais refléter l'Origin reçue."
                ),
                url=target, parameter="Access-Control-Allow-Origin",
                payload=f"Origin: {self.EVIL_ORIGIN}",
                evidence=f"ACAO={aco}, ACAC={acc}",
                confidence=95,
                cwe_id="CWE-942", owasp_id="A05:2021",
                cvss_base=7.5,
                detection_method="origin-reflection-test",
                source="module:cors-misconfig",
            ))
        elif aco == "*" and acc == "true":
            findings.append(Finding(
                type="cors-misconfig", severity="critical",
                title="CORS : * + Allow-Credentials=true",
                description=(
                    "Access-Control-Allow-Origin: * combiné avec Allow-Credentials: true "
                    "expose toutes les ressources authentifiées à n'importe quel site."
                ),
                recommendation="Soit ACAO=* sans credentials, soit ACAO explicite avec credentials. Jamais les deux.",
                url=target, parameter="Access-Control-Allow-Origin / Credentials",
                evidence=f"ACAO={aco}, ACAC={acc}",
                confidence=100,
                cwe_id="CWE-942", owasp_id="A05:2021",
                cvss_base=8.6,
                detection_method="header-inspection",
                source="module:cors-misconfig",
            ))
        elif aco.lower() == "null":
            findings.append(Finding(
                type="cors-misconfig", severity="medium",
                title="CORS : Allow-Origin: null",
                description="ACAO: null est exploitable depuis une iframe sandbox (qui a Origin: null).",
                recommendation="Ne jamais autoriser 'null'. Whitelist d'origines explicites uniquement.",
                url=target, parameter="Access-Control-Allow-Origin",
                evidence=f"ACAO={aco}",
                confidence=90,
                cwe_id="CWE-942", owasp_id="A05:2021",
                cvss_base=6.5,
                detection_method="header-inspection",
                source="module:cors-misconfig",
            ))

        return findings
