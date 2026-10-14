"""
Module : directory / file bruteforce.

Teste une wordlist de chemins communs (paths admin, VCS, configs, backups,
discovery files) et remonte ceux qui répondent autrement qu'en 404.

Rate-limited : 5 requêtes/s par défaut pour ne pas écraser la cible.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, urlunparse
import time
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding
from scanner.payloads import get_payloads


class DirBruteforceModule(ScannerModule):
    name = "dir-bruteforce"
    category = "discovery"
    title = "Directory & File Discovery"
    description = "Recherche de chemins communs : admin, VCS, configs, backups, discovery."
    default_enabled = False  # actif — peut générer du bruit

    # Rate-limit (req/s)
    RATE_LIMIT = 5

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        # Récup' baseline 404 pour comparer
        try:
            r_404 = http.get(base + "/_vulnscan_does_not_exist_xyz_42", context,
                             timeout=5, headers={"User-Agent": "VulnScan/1.2"},
                             allow_redirects=False)
            baseline_404_size = len(r_404.text)
            baseline_404_status = r_404.status_code
        except Exception:
            baseline_404_size = 0
            baseline_404_status = 404

        paths = get_payloads("dir_bruteforce")
        delay = 1.0 / self.RATE_LIMIT
        last_req = 0.0

        for entry in paths:
            # Rate limit
            sleep_time = delay - (time.time() - last_req)
            if sleep_time > 0:
                time.sleep(sleep_time)

            path = entry["path"]
            try:
                r = http.get(base + path, context, timeout=5,
                             headers={"User-Agent": "VulnScan/1.2"},
                             allow_redirects=False)
                last_req = time.time()
            except Exception:
                continue

            if r is None:
                continue

            status = r.status_code
            size = len(r.text)

            # Considéré comme trouvé si :
            # - 200/204/301/302/403 ET diffère du baseline 404
            is_found = (
                status in (200, 204, 401, 403) and
                not (status == baseline_404_status and abs(size - baseline_404_size) < 50)
            ) or (
                status in (301, 302) and "Location" in r.headers
            )

            if not is_found:
                continue

            findings.append(Finding(
                type="exposed-path",
                severity=entry["severity"],
                title=f"Chemin exposé : {path}",
                description=(
                    f"Le chemin {path} répond en HTTP {status} "
                    f"({size} octets). " +
                    (entry.get("description") or "Vérifier si cette ressource doit être publique.")
                ),
                recommendation=(
                    "Restreindre l'accès via authentification, .htaccess, ou supprimer "
                    "la ressource si elle ne devrait pas être en ligne."
                ),
                url=base + path,
                parameter=path,
                evidence=f"HTTP {status}, {size} octets",
                confidence=entry["confidence_hint"],
                cwe_id="CWE-538", owasp_id="A05:2021",
                cvss_base=8.6 if entry["severity"] == "critical" else
                          7.5 if entry["severity"] == "high" else
                          5.3 if entry["severity"] == "medium" else 3.7,
                detection_method="path-discovery",
                source="module:dir-bruteforce",
            ))
        return findings
