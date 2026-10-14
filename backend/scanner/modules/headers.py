"""
Module : en-têtes HTTP de sécurité.

Fait un fetch côté serveur de la cible et analyse les vrais headers :
  - CSP / X-Frame-Options / X-Content-Type-Options / HSTS / Referrer-Policy
  - Qualité de la CSP (unsafe-inline, unsafe-eval, wildcards)
  - Server: et X-Powered-By: bavards
  - Set-Cookie sans flags (Secure / HttpOnly / SameSite)
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding


class HeadersModule(ScannerModule):
    name = "headers"
    category = "misconfiguration"
    title = "Security Headers Auditor"
    description = "Vérifie la présence et la qualité des en-têtes HTTP de sécurité (CSP, HSTS, X-Frame-Options...)"
    default_enabled = True

    REQUIRED_HEADERS = [
        ("content-security-policy", "high", "high",
         "CSP manquant. Aucune restriction sur les origines de scripts/styles.",
         "Ajouter : Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'"),
        ("x-frame-options", "medium", "high",
         "X-Frame-Options manquant. Risque de clickjacking via iframe.",
         "Ajouter : X-Frame-Options: DENY (ou SAMEORIGIN)."),
        ("x-content-type-options", "low", "high",
         "X-Content-Type-Options manquant. Le navigateur peut deviner les types MIME.",
         "Ajouter : X-Content-Type-Options: nosniff"),
        ("referrer-policy", "low", "high",
         "Referrer-Policy manquant. Risque de fuite d'URL vers des sites tiers.",
         "Ajouter : Referrer-Policy: strict-origin-when-cross-origin"),
        ("permissions-policy", "low", "medium",
         "Permissions-Policy manquant. Aucune restriction sur géoloc, caméra, micro...",
         "Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        try:
            r = http.get(target, context, timeout=8, allow_redirects=True,
                         headers={"User-Agent": "VulnScan/1.2 (security-audit)"})
            headers = {k.lower(): v for k, v in r.headers.items()}
            url = r.url
            is_https = url.startswith("https://")
        except requests.exceptions.SSLError as e:
            return [Finding(
                type="tls", severity="high",
                description=f"Erreur SSL/TLS à la connexion : {str(e)[:120]}",
                recommendation="Vérifier la chaîne de certificats et la version TLS (≥ 1.2).",
                url=target, parameter="TLS handshake",
                confidence=95, cwe_id="CWE-326", owasp_id="A02:2021",
                cvss_base=7.4,
                detection_method="server-side-fetch",
                source="module:headers",
            )]
        except requests.exceptions.Timeout:
            return []
        except Exception:
            return []

        # 1. Headers requis
        for header, sev, conf_level, desc, rec in self.REQUIRED_HEADERS:
            if header not in headers:
                cvss = 7.0 if sev == "high" else 5.0 if sev == "medium" else 3.0
                findings.append(Finding(
                    type="missing-header", severity=sev,
                    description=desc, recommendation=rec,
                    url=url, parameter=header,
                    confidence={"high": 95, "medium": 80}.get(conf_level, 70),
                    cwe_id="CWE-693", owasp_id="A05:2021",
                    cvss_base=cvss,
                    detection_method="server-side-fetch",
                    source="module:headers",
                ))

        # 2. HSTS sur HTTPS
        if is_https and "strict-transport-security" not in headers:
            findings.append(Finding(
                type="missing-header", severity="high",
                description="HSTS manquant. Vulnérabilité de downgrade HTTPS→HTTP.",
                recommendation="Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                url=url, parameter="strict-transport-security",
                confidence=95, cwe_id="CWE-319", owasp_id="A02:2021",
                cvss_base=7.4,
                detection_method="server-side-fetch",
                source="module:headers",
            ))

        # 3. Qualité du CSP
        csp = headers.get("content-security-policy", "")
        if csp:
            weak = []
            if "'unsafe-inline'" in csp: weak.append("'unsafe-inline'")
            if "'unsafe-eval'" in csp:   weak.append("'unsafe-eval'")
            if re.search(r"script-src[^;]*\*", csp): weak.append("wildcard * dans script-src")
            if weak:
                findings.append(Finding(
                    type="weak-csp", severity="medium",
                    description=f"CSP affaiblie par : {', '.join(weak)}",
                    recommendation="Supprimer unsafe-inline/eval, préférer nonces ou hashes.",
                    url=url, parameter="Content-Security-Policy",
                    evidence=csp[:300],
                    confidence=90, cwe_id="CWE-1021", owasp_id="A05:2021",
                    cvss_base=5.4,
                    detection_method="server-side-fetch",
                    source="module:headers",
                ))

        # 4. Bavardage Server / X-Powered-By
        server = headers.get("server", "")
        if re.search(r"(apache|nginx|iis)/\d", server, re.I):
            findings.append(Finding(
                type="info-disclosure", severity="low",
                description=f"En-tête Server révèle la version : '{server}'",
                recommendation="Masquer la version (server_tokens off Nginx, ServerTokens Prod Apache).",
                url=url, parameter="Server", evidence=server,
                confidence=100, cwe_id="CWE-200", owasp_id="A05:2021",
                cvss_base=3.7,
                detection_method="server-side-fetch",
                source="module:headers",
            ))

        if "x-powered-by" in headers:
            findings.append(Finding(
                type="info-disclosure", severity="low",
                description=f"En-tête X-Powered-By révèle la techno : '{headers['x-powered-by']}'",
                recommendation="Désactiver côté serveur (expose_php=Off pour PHP, etc.).",
                url=url, parameter="X-Powered-By", evidence=headers["x-powered-by"],
                confidence=100, cwe_id="CWE-200", owasp_id="A05:2021",
                cvss_base=3.7,
                detection_method="server-side-fetch",
                source="module:headers",
            ))

        # 5. Cookies non sécurisés
        set_cookie = headers.get("set-cookie", "")
        if set_cookie:
            flags = []
            if "secure" not in set_cookie.lower() and is_https: flags.append("Secure")
            if "httponly" not in set_cookie.lower():            flags.append("HttpOnly")
            if "samesite" not in set_cookie.lower():            flags.append("SameSite")
            if flags:
                findings.append(Finding(
                    type="insecure-cookie", severity="medium",
                    description=f"Cookie sans flag(s) : {', '.join(flags)}",
                    recommendation="Configurer Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict",
                    url=url, parameter="Set-Cookie", evidence=set_cookie[:200],
                    confidence=95, cwe_id="CWE-1004", owasp_id="A05:2021",
                    cvss_base=5.4,
                    detection_method="server-side-fetch",
                    source="module:headers",
                ))

        return findings
