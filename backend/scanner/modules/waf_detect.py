"""
Module : WAF Detection.

Tente d'identifier la présence d'un WAF en :
  1. Envoyant une requête normale → analyse des headers (CF-RAY, X-Akamai, etc.)
  2. Envoyant une requête volontairement malveillante (UA SQLi simple) → si bloquée
     mais que la baseline passe, indice WAF
  3. Comparant le body si "Attention Required", "Reference #", etc.

Si WAF détecté : on met l'info dans le contexte pour que les autres modules
puissent muter leurs payloads (via scanner.core.waf.mutate).
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import re

from scanner.core.module_base import ScannerModule, Finding
from scanner.core.waf import detect_waf


class WafDetectModule(ScannerModule):
    name = "waf-detect"
    category = "discovery"
    title = "WAF Detection"
    description = "Détecte la présence d'un Web Application Firewall."
    default_enabled = True

    MALICIOUS_UA = "Mozilla/5.0 ' OR 1=1-- <script>alert(1)</script>"

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []

        try:
            # 1. Baseline
            r_base = requests.get(target, timeout=8,
                                  headers={"User-Agent": "VulnScan/1.5"})
        except Exception:
            return []

        waf_baseline = detect_waf(dict(r_base.headers), r_base.text)

        # 2. Requête malveillante
        waf_malicious = None
        try:
            r_mal = requests.get(target, timeout=8,
                                 headers={"User-Agent": self.MALICIOUS_UA})
            waf_malicious = detect_waf(dict(r_mal.headers), r_mal.text)
        except Exception:
            pass

        waf_name = waf_baseline or waf_malicious
        if not waf_name:
            return []

        # Mettre dans le contexte pour usage par les autres modules
        context["waf"] = {"name": waf_name, "detected_at": target}

        return [Finding(
            type="waf-detected", severity="info",
            title=f"WAF détecté : {waf_name}",
            description=(
                f"La cible est protégée par {waf_name}. Les payloads basiques pourront être bloqués. "
                "Les modules d'injection utiliseront automatiquement des variantes mutées "
                "(case-mix, URL encoding, comment injection) pour tenter de bypass."
            ),
            recommendation=(
                "Maintenir le WAF à jour, configurer correctement les règles personnalisées, "
                "et NE JAMAIS s'y reposer comme seule couche de défense (defense in depth)."
            ),
            url=target, parameter="WAF presence",
            evidence=f"WAF: {waf_name}",
            confidence=90,
            cwe_id="CWE-1287", owasp_id="A05:2021",
            cvss_base=0.0,  # Pas une vuln, juste une info
            detection_method="header-and-body-signatures",
            source="module:waf-detect",
        )]
