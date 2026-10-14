"""
Module : Open Redirect.

Vérifie si un paramètre URL provoque une redirection 3xx vers un hôte arbitraire
(non-cible). Test passif (suit pas la redirect) + actif (Location header).

OWASP A01 / CWE-601.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
import re

from scanner.core.module_base import ScannerModule, Finding


class OpenRedirectModule(ScannerModule):
    name = "open-redirect"
    category = "misconfiguration"
    title = "Open Redirect"
    description = "Détecte les paramètres provoquant une redirection vers un hôte externe."
    default_enabled = False

    REDIRECT_PARAMS = {"next", "url", "redirect", "redirect_uri", "return",
                       "return_url", "returnurl", "callback", "continue",
                       "dest", "destination", "goto", "rurl"}

    CANARY_HOST = "vulnscan-canary.example.com"  # ne sera jamais joint

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))
        target_host = parsed.hostname or ""

        for param_name in params:
            if param_name.lower() not in self.REDIRECT_PARAMS:
                continue

            canary_url = f"https://{self.CANARY_HOST}/lab"
            new_params = dict(params)
            new_params[param_name] = canary_url
            test_url = urlunparse(parsed._replace(query=urlencode(new_params)))

            try:
                r = requests.get(test_url, timeout=8, allow_redirects=False,
                                 headers={"User-Agent": "VulnScan/1.2"})
                if r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location", "")
                    loc_host = urlparse(location).hostname or ""
                    if self.CANARY_HOST in location or (loc_host and loc_host != target_host):
                        findings.append(Finding(
                            type="open-redirect", severity="medium",
                            title="Open Redirect confirmé",
                            description=(
                                f"Paramètre '{param_name}' redirige vers un hôte externe arbitraire "
                                f"({location}). Risque de phishing avec URL légitime."
                            ),
                            recommendation=(
                                "Valider la cible contre une whitelist d'URLs (ou ne garder que le chemin). "
                                "Refuser tout schéma autre que https et tout host externe."
                            ),
                            url=target, parameter=param_name,
                            payload=canary_url,
                            evidence=f"HTTP {r.status_code} → Location: {location}",
                            confidence=95,
                            cwe_id="CWE-601", owasp_id="A01:2021",
                            cvss_base=6.1,
                            detection_method="canary-redirect",
                            source="module:open-redirect",
                        ))
            except Exception:
                continue
        return findings
