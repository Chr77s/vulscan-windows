"""
Module : Rate Limiting check.

Envoie une rafale de 15 requêtes vers une URL "sensible" (login, register, api)
et observe si le serveur applique du throttling :
  - HTTP 429 Too Many Requests
  - Headers Retry-After, X-RateLimit-Remaining
  - Blocage IP visible (403 après quelques tentatives)

Si aucun signal de throttling → brute-force trivial = vuln A07 / CWE-307.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse
import requests
import time
import re

from scanner.core.module_base import ScannerModule, Finding


class RateLimitModule(ScannerModule):
    name = "rate-limit"
    category = "auth"
    title = "Rate Limiting Audit"
    description = "Envoie une rafale et observe si le serveur applique un throttling."
    default_enabled = False  # actif — 15 req en 3s

    SENSITIVE_PATH_HINTS = ("login", "signin", "auth", "register", "api/auth", "reset", "forgot")
    BURST_SIZE = 15

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []

        # On ne teste que si l'URL paraît sensible — sinon polluant.
        if not any(hint in target.lower() for hint in self.SENSITIVE_PATH_HINTS):
            return []

        statuses = []
        retry_after = None
        rate_remaining = None

        start = time.time()
        for i in range(self.BURST_SIZE):
            try:
                r = requests.post(target, data={"username": "test", "password": "wrong"},
                                  timeout=5, headers={"User-Agent": "VulnScan/1.2"})
                statuses.append(r.status_code)
                if r.headers.get("Retry-After"):
                    retry_after = r.headers["Retry-After"]
                if r.headers.get("X-RateLimit-Remaining"):
                    rate_remaining = r.headers["X-RateLimit-Remaining"]
                if r.status_code == 429:
                    break
            except Exception:
                statuses.append(0)
        duration = time.time() - start

        has_throttling = (
            429 in statuses or
            retry_after is not None or
            rate_remaining is not None
        )

        if has_throttling:
            return []  # rien à signaler — c'est bon

        # Tous les statuts identiques → pas de différenciation, pas de blocage
        if statuses and len(set(statuses)) <= 2 and 429 not in statuses:
            return [Finding(
                type="rate-limit-missing", severity="high",
                title="Pas de rate-limiting sur endpoint sensible",
                description=(
                    f"{self.BURST_SIZE} requêtes en {duration:.1f}s vers {target} sans throttling "
                    f"observable. Codes : {set(statuses)}. Brute-force trivial."
                ),
                recommendation=(
                    "Imposer un rate-limit côté serveur (ex: 5 tentatives/minute par IP), "
                    "renvoyer HTTP 429 + Retry-After, et logger les tentatives."
                ),
                url=target, parameter="(endpoint)",
                evidence=f"Burst {self.BURST_SIZE} POST en {duration:.1f}s → statuts {statuses[:5]}...",
                confidence=85,
                cwe_id="CWE-307", owasp_id="A07:2021",
                cvss_base=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                detection_method="burst-test",
                source="module:rate-limit",
            )]
        return []
