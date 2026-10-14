"""
Module : Technology Fingerprinting.

Identifie CMS, frameworks, langages et serveurs via :
  - Headers HTTP (Server, X-Powered-By, X-Generator)
  - Meta tags <meta name="generator">
  - URLs de scripts/CSS (jquery, react, vue, angular, bootstrap)
  - Patterns HTML (wp-content, drupal, mediawiki)
  - Cookies typiques (JSESSIONID, PHPSESSID, ASP.NET_SessionId)

L'identification de la techno n'est pas une vuln en soi (sévérité info)
mais elle aide les pentesters et alimente d'autres modules (ex: jQuery
vulnérable → CVE check).
"""
from __future__ import annotations
from typing import List, Dict, Any, Tuple
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding


class TechFingerprintModule(ScannerModule):
    name = "tech-fingerprint"
    category = "discovery"
    title = "Technology Fingerprinting"
    description = "Identifie CMS, frameworks, langages et serveurs présents."
    default_enabled = True

    # (regex pattern, source, label)
    FINGERPRINTS_HEADERS = [
        (re.compile(r"apache", re.I),                  "Server",           "Apache HTTP Server"),
        (re.compile(r"nginx", re.I),                   "Server",           "Nginx"),
        (re.compile(r"iis", re.I),                     "Server",           "Microsoft IIS"),
        (re.compile(r"cloudflare", re.I),              "Server",           "Cloudflare"),
        (re.compile(r"php", re.I),                     "X-Powered-By",     "PHP"),
        (re.compile(r"asp\.net", re.I),                "X-Powered-By",     "ASP.NET"),
        (re.compile(r"express", re.I),                 "X-Powered-By",     "Express.js (Node.js)"),
        (re.compile(r"django", re.I),                  "Server",           "Django"),
    ]

    FINGERPRINTS_HTML = [
        (re.compile(r"wp-content/|wp-includes/", re.I),                 "WordPress"),
        (re.compile(r"/sites/default/files/|drupal\.js", re.I),         "Drupal"),
        (re.compile(r"/skin/frontend/|var/connect.php", re.I),          "Magento"),
        (re.compile(r"<meta\s+name=[\"']generator[\"']\s+content=[\"']([^\"']+)", re.I), "META:Generator"),
        (re.compile(r"window\.__NUXT__", re.I),                         "Nuxt.js"),
        (re.compile(r"window\.__NEXT_DATA__", re.I),                    "Next.js"),
        (re.compile(r"ng-version=", re.I),                              "Angular"),
        (re.compile(r"data-reactroot", re.I),                           "React"),
        (re.compile(r"jquery[.\-](\d+\.\d+\.\d+)", re.I),               "jQuery (version match)"),
    ]

    COOKIE_SIGNATURES = [
        ("PHPSESSID",           "PHP backend"),
        ("JSESSIONID",          "Java backend"),
        ("ASP.NET_SessionId",   "ASP.NET backend"),
        ("CFID",                "ColdFusion"),
        ("connect.sid",         "Express.js (Node.js)"),
        ("XSRF-TOKEN",          "Laravel ou Angular"),
        ("ci_session",          "CodeIgniter"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        detected: List[Tuple[str, str]] = []  # (label, evidence)

        try:
            r = http.get(target, context, timeout=8, headers={"User-Agent": "VulnScan/1.2"})
            headers = {k.lower(): v for k, v in r.headers.items()}
            body = r.text
            set_cookie = headers.get("set-cookie", "")
        except Exception:
            return []

        # 1. Headers
        for pattern, header_name, label in self.FINGERPRINTS_HEADERS:
            val = headers.get(header_name.lower(), "")
            if val and pattern.search(val):
                detected.append((label, f"{header_name}: {val}"))

        # 2. HTML
        for pattern, label in self.FINGERPRINTS_HTML:
            m = pattern.search(body)
            if m:
                if label == "META:Generator":
                    label = f"Generator: {m.group(1)}"
                evidence = m.group(0)[:120]
                detected.append((label, evidence))

        # 3. Cookies
        for cookie_name, label in self.COOKIE_SIGNATURES:
            if cookie_name in set_cookie:
                detected.append((label, f"Cookie: {cookie_name}"))

        # Construire UN finding info qui résume tout
        if detected:
            techs = list(dict.fromkeys([d[0] for d in detected]))  # déduplication ordre stable
            findings.append(Finding(
                type="tech-fingerprint", severity="info",
                title=f"Technologies détectées : {', '.join(techs[:5])}",
                description=(
                    f"{len(techs)} composant(s) identifié(s) : {', '.join(techs)}. "
                    "Cette information facilite la recherche de CVE publiques ciblées."
                ),
                recommendation=(
                    "Masquer les en-têtes (Server, X-Powered-By) et meta generator en production. "
                    "Maintenir à jour les composants identifiés."
                ),
                url=target, parameter="(empreinte)",
                evidence="\n".join(f"• {l}: {e}" for l, e in detected[:8]),
                confidence=95,
                cwe_id="CWE-200", owasp_id="A05:2021",
                cvss_base=3.7,
                detection_method="headers + html + cookies fingerprinting",
                source="module:tech-fingerprint",
            ))
        return findings
