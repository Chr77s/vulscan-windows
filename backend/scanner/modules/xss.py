"""
Module : détection XSS reflété (semi-actif).

Stratégie :
  1. Pour chaque paramètre GET, injecte un marqueur unique non-malveillant
     (string aléatoire) et vérifie s'il est reflété tel quel dans la réponse.
  2. Si reflété : test des contextes (HTML, attribut, JS, URL) et propose
     les payloads adaptés.

Le payload réel n'est pas exécuté — on observe juste si le marqueur ressort,
ce qui ne casse rien et reste défensif.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
import secrets
import re

from scanner.core.module_base import ScannerModule, Finding


class XssModule(ScannerModule):
    name = "xss"
    category = "injection"
    title = "Cross-Site Scripting (Reflected)"
    description = "Détecte les paramètres GET réfléchis dans la réponse — base d'une XSS reflétée."
    default_enabled = False  # Module actif

    PAYLOAD_CATALOG = {
        "html_context":      "<script>alert(1)</script>",
        "attribute_context": '" onmouseover="alert(1)',
        "js_context":        "';alert(1);//",
        "url_context":       "javascript:alert(1)",
        "svg_context":       "<svg onload=alert(1)>",
        "img_context":       '<img src=x onerror=alert(1)>',
    }

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))
        if not params:
            return []

        for param_name, base_value in params.items():
            marker = "vsx" + secrets.token_hex(4)  # marqueur unique
            test_params = dict(params)
            test_params[param_name] = marker
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                r = requests.get(test_url, timeout=8,
                                 headers={"User-Agent": "VulnScan/1.2"})
                body = r.text
            except Exception:
                continue

            if marker not in body:
                continue  # pas réfléchi

            # Détecter le contexte du reflet
            contexts = self._detect_contexts(body, marker)
            payloads = [self.PAYLOAD_CATALOG[c] for c in contexts if c in self.PAYLOAD_CATALOG]

            findings.append(Finding(
                type="xss", severity="high",
                title="Reflected XSS — Parameter Reflection",
                description=(
                    f"Le paramètre '{param_name}' est réfléchi tel quel dans la réponse "
                    f"({len(contexts)} contexte(s) détecté(s) : {', '.join(contexts) or 'html'}). "
                    "Un payload de script pourrait être exécuté."
                ),
                recommendation=(
                    "Encoder la sortie selon le contexte (HTMLEntity, attribute, JS, URL). "
                    "Mettre en place une CSP stricte. Côté serveur : DOMPurify, htmlspecialchars(), etc."
                ),
                url=target, parameter=param_name,
                payload=payloads[0] if payloads else self.PAYLOAD_CATALOG["html_context"],
                evidence=self._extract_context(body, marker),
                confidence=85,
                cwe_id="CWE-79", owasp_id="A03:2021",
                cvss_base=6.1,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                detection_method="reflection-marker",
                source="module:xss",
            ))
        return findings

    @staticmethod
    def _detect_contexts(body: str, marker: str) -> List[str]:
        """Identifie dans quel contexte HTML le marqueur apparaît."""
        contexts = []
        idx = body.find(marker)
        if idx == -1:
            return contexts
        before = body[max(0, idx - 80):idx]
        after  = body[idx:idx + 80]

        # JS context
        if re.search(r"<script[^>]*>[^<]*$", before, re.I) or "var " in before[-30:]:
            contexts.append("js_context")
        # Attribute context (entre " ou ')
        elif re.search(r'=["\'][^"\']*$', before):
            contexts.append("attribute_context")
        # URL context (href, src)
        elif re.search(r'(href|src|action)\s*=\s*["\']?[^"\'>]*$', before, re.I):
            contexts.append("url_context")
        # HTML context (cas par défaut)
        else:
            contexts.append("html_context")
        return contexts

    @staticmethod
    def _extract_context(body: str, marker: str, span: int = 100) -> str:
        idx = body.find(marker)
        if idx == -1:
            return ""
        return body[max(0, idx - span):idx + len(marker) + span].replace("\n", " ").strip()
