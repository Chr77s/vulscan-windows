"""
Module : info disclosure — analyse du body de la page pour trouver
des secrets, clés API, JWT, chemins, stack traces, etc.

Plus complet que la version content-script car BeautifulSoup permet
d'isoler les commentaires HTML et les blocs <script>, sans bruit.
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import re

from scanner.core.module_base import ScannerModule, Finding

try:
    from bs4 import BeautifulSoup, Comment
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


class InfoDisclosureModule(ScannerModule):
    name = "info-disclosure"
    category = "info"
    title = "Information Disclosure"
    description = "Recherche dans le body : secrets, JWT, stack traces, chemins serveur, IPs internes."
    default_enabled = True

    PATTERNS = [
        ("Clé API", "critical", 90, r"\b(sk_live_|sk_test_|pk_live_|api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]?\s*['\"]?[\w\-]{20,}", "CWE-798"),
        ("JWT exposé", "high", 95, r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "CWE-200"),
        ("Stack trace", "high", 90, r"(?:Traceback \(most recent call last\)|Exception in thread|at\s+[\w.$]+\s+\([^)]*\.(java|js|py|rb):\d+)", "CWE-209"),
        ("Connexion DB", "critical", 95, r"\b(?:postgres|mysql|mongodb|redis)://[^\s'\"<>]+", "CWE-798"),
        ("Chemin serveur Linux", "medium", 80, r"(?:/var/www/|/home/[a-z]+/|/etc/(?:passwd|shadow))", "CWE-200"),
        ("Chemin serveur Windows", "medium", 80, r"C:\\\\Users\\\\\w+\\\\", "CWE-200"),
        ("IP privée", "low", 60, r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3})\b", "CWE-200"),
        ("Email exposé", "low", 70, r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "CWE-200"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []

        try:
            r = requests.get(target, timeout=8, headers={"User-Agent": "VulnScan/1.2"})
            body = r.text
        except Exception:
            return []

        # On scanne sur l'ensemble du body
        sources = [body]

        # Si BS4 dispo, on regarde aussi spécifiquement les commentaires (souvent oubliés en prod)
        if HAS_BS4:
            try:
                soup = BeautifulSoup(body, "html.parser")
                for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
                    sources.append(str(c))
            except Exception:
                pass

        findings: List[Finding] = []
        seen = set()  # déduplication

        for name, severity, conf, pattern, cwe in self.PATTERNS:
            for source in sources:
                matches = list(re.finditer(pattern, source, re.IGNORECASE))[:5]
                for match in matches:
                    sig = (name, match.group(0)[:80])
                    if sig in seen:
                        continue
                    seen.add(sig)

                    findings.append(Finding(
                        type="sensitive-data", severity=severity,
                        title=f"{name} dans le code source",
                        description=f"{name} détecté dans le HTML/JS public de la page.",
                        recommendation="Ne jamais exposer de secrets côté client. Utiliser des variables d'environnement serveur.",
                        url=target, parameter=f"{name}",
                        evidence=match.group(0)[:120],
                        confidence=conf,
                        cwe_id=cwe, owasp_id="A02:2021",
                        cvss_base=8.0 if severity == "critical" else 5.5 if severity == "medium" else 3.5,
                        detection_method="passive-regex-scan",
                        source="module:info-disclosure",
                    ))
        return findings
