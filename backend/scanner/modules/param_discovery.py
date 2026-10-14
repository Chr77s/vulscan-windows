"""
Module : Hidden Parameter Discovery (Arjun-like).

Pour une URL donnée, envoie une requête avec chaque nom de paramètre de la
wordlist. Si la réponse change significativement vs baseline, le paramètre
est "actif" → il est traité par le serveur mais pas documenté.

Risques :
  - feature flags cachés (?debug=1, ?show_errors=1) → leak d'info
  - bypass de contrôles (?admin=1, ?role=admin)
  - paramètres internes (token, key, secret) qu'on peut tester

Stratégie :
  - Baseline GET de l'URL
  - Pour chaque nom dans la wordlist : ?nom=12345 et compare la réponse
  - Si Δ > seuil, on rapporte
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
import requests
import difflib
import re

from scanner.core.module_base import ScannerModule, Finding
from scanner.payloads import get_payloads


class ParamDiscoveryModule(ScannerModule):
    name = "param-discovery"
    category = "discovery"
    title = "Hidden Parameter Discovery"
    description = "Brute-force la wordlist de noms de params pour découvrir les hidden parameters."
    default_enabled = False  # actif, ~200 requêtes

    DIFF_THRESHOLD = 0.10  # 10% de différence = signal
    SAMPLE_VALUE = "VS12345"  # valeur de test qu'on peut chercher dans la réponse

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []

        # Baseline
        try:
            r_base = requests.get(target, timeout=8,
                                  headers={"User-Agent": "VulnScan/1.3"})
            body_base = r_base.text
            base_size = len(body_base)
        except Exception:
            return findings

        # Wordlist depuis le catalogue
        wordlist = get_payloads("param_names")
        if not wordlist:
            return findings

        parsed = urlparse(target)
        existing_params = dict(parse_qsl(parsed.query))

        discovered: List[Dict[str, Any]] = []
        for item in wordlist:
            name = item["name"]
            if name in existing_params:
                continue

            test_params = dict(existing_params)
            test_params[name] = self.SAMPLE_VALUE
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                r = requests.get(test_url, timeout=5,
                                 headers={"User-Agent": "VulnScan/1.3"})
                body = r.text
            except Exception:
                continue

            # Signal fort : la valeur sample apparaît dans la réponse
            if self.SAMPLE_VALUE in body and self.SAMPLE_VALUE not in body_base:
                discovered.append({
                    "name": name, "category": item.get("category", "common"),
                    "signal": "value-reflected", "confidence": 95,
                })
                continue

            # Signal moyen : différence de taille / contenu
            size_diff = abs(len(body) - base_size) / max(base_size, 1)
            if size_diff > self.DIFF_THRESHOLD:
                ratio = difflib.SequenceMatcher(None, body_base, body).ratio()
                if ratio < (1.0 - self.DIFF_THRESHOLD):
                    discovered.append({
                        "name": name, "category": item.get("category", "common"),
                        "signal": "response-diff", "confidence": 60,
                        "ratio": round(ratio, 2),
                    })

        # Construire un finding par paramètre découvert
        for d in discovered[:15]:  # limite affichage
            sev = "high" if d["signal"] == "value-reflected" else "medium"
            cwe = "CWE-1287" if d["category"] == "auth" else "CWE-200"

            findings.append(Finding(
                type="hidden-parameter", severity=sev,
                title=f"Paramètre caché détecté : '{d['name']}'",
                description=(
                    f"Le serveur traite un paramètre '{d['name']}' non documenté "
                    f"({d['signal']}). Catégorie : {d['category']}. "
                    "Souvent un feature flag, mode debug ou contrôle d'accès."
                ),
                recommendation=(
                    "Désactiver tout paramètre non documenté en production. "
                    "Logger les requêtes contenant des params inattendus."
                ),
                url=target, parameter=d["name"],
                payload=f"?{d['name']}={self.SAMPLE_VALUE}",
                evidence=f"Signal: {d['signal']}, conf: {d['confidence']}%",
                confidence=d["confidence"],
                cwe_id=cwe, owasp_id="A05:2021",
                cvss_base=6.5 if sev == "high" else 4.3,
                detection_method="wordlist-fuzz",
                source="module:param-discovery",
            ))

        return findings
