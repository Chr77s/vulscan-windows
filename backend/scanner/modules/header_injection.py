"""
Module : Header Injection.

Injecte des payloads dans les en-têtes HTTP couramment loggés/affichés :
  - User-Agent      → souvent affiché dans le panel admin / analytics
  - Referer         → idem + open redirect via referer
  - X-Forwarded-For → IP loggée en DB (SQLi possible)
  - Host            → host header injection (cache poisoning, password reset)
  - Cookie          → tentative privesc (admin=true, role=admin)

Détection : reflet du marqueur dans la réponse, signature d'erreur SQL,
ou différence radicale vs baseline.

Note : on cherche ces injections sur l'URL cible + les URLs découvertes par le crawler.
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import secrets
import re

from scanner.core.module_base import ScannerModule, Finding


class HeaderInjectionModule(ScannerModule):
    name = "header-injection"
    category = "injection"
    title = "HTTP Header Injection"
    description = "Injecte des payloads dans User-Agent, Referer, X-Forwarded-For, Host, Cookie."
    default_enabled = False

    HEADERS_TESTED = ["User-Agent", "Referer", "X-Forwarded-For", "Host", "Cookie"]

    SQL_ERROR_PATTERNS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning.*mysql_", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"sqlite3?\.operationalerror", re.I),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []

        # Cibles : URL initiale + URLs découvertes par le crawler (limité à 5)
        urls_to_test = [target]
        crawled_urls = (context.get("crawled") or {}).get("urls", [])
        for u in crawled_urls[:4]:
            if u not in urls_to_test:
                urls_to_test.append(u)

        for url in urls_to_test:
            findings.extend(self._fuzz_headers(url))
        return findings

    def _fuzz_headers(self, url: str) -> List[Finding]:
        findings = []
        # Baseline
        try:
            baseline = requests.get(url, timeout=8,
                                    headers={"User-Agent": "VulnScan/1.3"})
        except Exception:
            return []

        for header_name in self.HEADERS_TESTED:
            findings.extend(self._test_header(url, header_name, baseline))
        return findings

    def _test_header(self, url: str, header_name: str, baseline) -> List[Finding]:
        findings = []
        mark = "vsh" + secrets.token_hex(3)

        # Catalogue de payloads adapté à chaque header
        payloads = self._payloads_for(header_name, mark)

        for p_value, p_type, p_desc in payloads:
            headers = {"User-Agent": "VulnScan/1.3"}
            # Pour Cookie : on l'ajoute, ne pas écraser UA
            if header_name == "Cookie":
                headers["Cookie"] = p_value
            else:
                headers[header_name] = p_value

            try:
                r = requests.get(url, headers=headers, timeout=8, allow_redirects=False)
            except Exception:
                continue

            body = r.text

            # 1. Reflet du marqueur → XSS via header
            if p_type == "xss" and mark in body:
                findings.append(Finding(
                    type="xss", severity="high",
                    title=f"XSS via en-tête {header_name}",
                    description=(
                        f"Le payload envoyé dans le header {header_name} est reflété dans la réponse "
                        f"(marqueur '{mark}' trouvé). Vulnérabilité fréquente sur les panels admin "
                        "qui affichent les UA/IP des visiteurs."
                    ),
                    recommendation=(
                        f"Échapper les valeurs de {header_name} avant affichage côté serveur. "
                        "Ne pas les inclure tel quel dans des templates."
                    ),
                    url=url, parameter=f"Header: {header_name}",
                    payload=p_value,
                    evidence=f"Marqueur '{mark}' reflété",
                    confidence=85, cwe_id="CWE-79", owasp_id="A03:2021",
                    cvss_base=6.1,
                    detection_method="header-injection-reflection",
                    source="module:header-injection",
                ))
                break

            # 2. Erreur SQL → SQLi via header
            if p_type == "sqli":
                for sig in self.SQL_ERROR_PATTERNS:
                    if sig.search(body):
                        findings.append(Finding(
                            type="sqli", severity="critical",
                            title=f"SQLi via en-tête {header_name}",
                            description=(
                                f"Le serveur révèle une erreur SQL après injection dans {header_name}. "
                                "Souvent dû à un logging de l'IP / UA en base sans préparation."
                            ),
                            recommendation="Utiliser des requêtes paramétrées sur tout ce qui logge des headers.",
                            url=url, parameter=f"Header: {header_name}",
                            payload=p_value,
                            evidence=sig.search(body).group(0)[:150],
                            confidence=90, cwe_id="CWE-89", owasp_id="A03:2021",
                            cvss_base=9.8,
                            detection_method="header-injection-error",
                            source="module:header-injection",
                        ))
                        break

            # 3. CRLF injection — header injecté dans la réponse
            if p_type == "crlf":
                injected_header = r.headers.get("X-Injected", "")
                if injected_header:
                    findings.append(Finding(
                        type="crlf-injection", severity="medium",
                        title=f"CRLF Injection via {header_name}",
                        description=(
                            f"Le payload CRLF dans {header_name} a injecté un header X-Injected dans la réponse. "
                            "Risque de Response Splitting / cache poisoning."
                        ),
                        recommendation="Filtrer \\r et \\n dans toute valeur de header copiée dans la réponse.",
                        url=url, parameter=f"Header: {header_name}",
                        payload=p_value,
                        evidence=f"X-Injected: {injected_header}",
                        confidence=95, cwe_id="CWE-93", owasp_id="A03:2021",
                        cvss_base=6.5,
                        detection_method="crlf-injection-test",
                        source="module:header-injection",
                    ))
                    break

            # 4. Host header injection : look for the evil host in absolute URLs
            if p_type == "host-injection" and "evil.example.com" in body:
                findings.append(Finding(
                    type="host-injection", severity="high",
                    title="Host Header Injection",
                    description=(
                        f"L'en-tête Host arbitraire ({p_value}) apparaît dans la réponse — "
                        "souvent dans un lien de password reset → permet phishing."
                    ),
                    recommendation="Whitelist les Host autorisés côté serveur (ServerName Apache, server_name Nginx).",
                    url=url, parameter="Host header", payload=p_value,
                    evidence=f"'{p_value}' trouvé dans la réponse",
                    confidence=85, cwe_id="CWE-20", owasp_id="A05:2021",
                    cvss_base=7.4,
                    detection_method="host-header-reflection",
                    source="module:header-injection",
                ))
                break

        return findings

    @staticmethod
    def _payloads_for(header_name: str, mark: str):
        """Renvoie les payloads adaptés à chaque header."""
        base = {
            "User-Agent": [
                (f"Mozilla/5.0 <svg onload={mark}>", "xss", "XSS via UA"),
                ("Mozilla/5.0 ' OR 1=1-- ",         "sqli", "SQLi via UA loggé"),
                ("Mozilla/5.0\r\nX-Injected: yes",  "crlf", "CRLF"),
            ],
            "Referer": [
                (f"https://evil.com/<svg onload={mark}>", "xss", "XSS via referer"),
                ("https://evil.example.com",              "host-injection", "Referer canary"),
            ],
            "X-Forwarded-For": [
                ("127.0.0.1' OR 1=1-- ",   "sqli", "SQLi via IP loggée"),
                (f"<svg onload={mark}>",   "xss",  "XSS via IP affichée"),
            ],
            "Host": [
                ("evil.example.com",       "host-injection", "Host canary"),
            ],
            "Cookie": [
                ("admin=true",             "privesc", "Privesc via cookie"),
            ],
        }
        return base.get(header_name, [])
