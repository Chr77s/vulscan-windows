"""
Module : Subdomain Enumeration.

Brute-force DNS d'une wordlist de sous-domaines communs sur le domaine cible,
+ lookup Certificate Transparency (crt.sh) si réseau dispo.

Cas d'usage : découvrir les hosts oubliés (dev-api, staging, beta, admin)
qui sont souvent plus vulnérables que la prod (config par défaut, anciens
endpoints, secrets exposés).

Limites :
  - DNS brute-force séquentiel — peut être lent
  - Pas de certificate transparency en mode hors-ligne
  - Ne descend pas plus profond que 1 niveau

⚠️ N'utilise que pour les domaines pour lesquels vous avez autorisation.
"""
from __future__ import annotations
from typing import List, Dict, Any, Set
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import socket
import requests
import re

from scanner.core.module_base import ScannerModule, Finding


COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "dns",
    "api", "api-v1", "api-v2", "rest", "graphql", "ws", "websocket",
    "admin", "administrator", "manager", "portal", "dashboard",
    "dev", "develop", "development", "test", "testing", "staging", "stage",
    "preprod", "prerelease", "uat", "beta", "alpha", "demo",
    "shop", "store", "blog", "news", "forum", "wiki", "docs", "doc",
    "help", "support", "kb", "status", "uptime",
    "git", "gitlab", "github", "jenkins", "ci", "cd", "build",
    "auth", "sso", "oauth", "login", "id", "account", "accounts",
    "cdn", "static", "assets", "img", "images", "files", "uploads",
    "backup", "backups", "old", "legacy", "archive",
    "mx", "vpn", "ssh", "remote", "office", "internal", "intranet",
    "m", "mobile", "app", "apps", "web",
]


class SubdomainEnumModule(ScannerModule):
    name = "subdomain-enum"
    category = "discovery"
    title = "Subdomain Enumeration"
    description = "Brute-force DNS de sous-domaines communs + Certificate Transparency."
    default_enabled = False  # peut être lent

    MAX_THREADS = 20

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        host = urlparse(target).hostname
        if not host:
            return []

        # On extrait le domaine racine (ex: app.example.com → example.com)
        parts = host.split(".")
        if len(parts) < 2:
            return []
        # Heuristique simple : on garde les 2 derniers labels (ne marche pas pour
        # les ccTLDs composés comme .co.uk, mais OK pour la plupart des cas)
        root_domain = ".".join(parts[-2:])

        if root_domain in ("localhost", "local"):
            return []  # pas pertinent

        # 1. Brute-force DNS
        found = self._dns_bruteforce(root_domain)

        # 2. Certificate Transparency (crt.sh)
        ct_found = self._cert_transparency(root_domain)
        found.update(ct_found)

        if not found:
            return []

        # Construire UN finding qui résume tous les sous-domaines
        sub_list = sorted(found)
        return [Finding(
            type="subdomain-found",
            severity="info" if len(sub_list) < 5 else "low",
            title=f"{len(sub_list)} sous-domaine(s) découvert(s) pour {root_domain}",
            description=(
                f"Énumération de {root_domain} : {len(sub_list)} sous-domaine(s) actifs. "
                "Chacun étend la surface d'attaque et mérite un scan indépendant."
            ),
            recommendation=(
                "Inventorier régulièrement les sous-domaines actifs. Désactiver ceux qui "
                "ne sont plus utilisés (subdomain takeover sinon). Soumettre chaque host à un scan."
            ),
            url=target, parameter=root_domain,
            evidence="\n".join("• " + s for s in sub_list[:20]),
            confidence=100,
            cwe_id="CWE-200", owasp_id="A05:2021",
            cvss_base=3.7,
            detection_method="dns-bruteforce + certificate-transparency",
            source="module:subdomain-enum",
        )]

    def _dns_bruteforce(self, root: str) -> Set[str]:
        found = set()

        def _resolve(name: str):
            full = f"{name}.{root}"
            try:
                socket.gethostbyname(full)
                return full
            except (socket.gaierror, socket.timeout):
                return None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=self.MAX_THREADS) as pool:
            futures = {pool.submit(_resolve, name): name for name in COMMON_SUBDOMAINS}
            for fut in as_completed(futures):
                result = fut.result()
                if result:
                    found.add(result)
        return found

    def _cert_transparency(self, root: str) -> Set[str]:
        """Interroge crt.sh — gratuit, public, mais nécessite internet."""
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{root}&output=json", timeout=8,
                             headers={"User-Agent": "VulnScan/1.5"})
            if not r.ok:
                return set()
            entries = r.json()
            found = set()
            for entry in entries[:200]:  # limit
                name = entry.get("name_value", "")
                for n in name.split("\n"):
                    n = n.strip().lower()
                    if n.endswith("." + root) and "*" not in n:
                        found.add(n)
            return found
        except Exception:
            return set()
