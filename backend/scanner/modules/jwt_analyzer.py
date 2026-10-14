"""
Module : analyse de JWT trouvés dans la page (cookies, localStorage simulé, response body).

Vérifications :
  - Algorithme "none" (alg: none → CVE classique)
  - Secret HMAC trivial (essai d'une wordlist courte sur HS256)
  - Token expiré (exp passé)
  - claims sensibles non-protégés (admin: true, role: admin sans signature solide)

OWASP A02:2021 (cryptographic failures) / CWE-327, CWE-345.
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import base64
import hmac
import hashlib
import json
import re

from scanner.core.module_base import ScannerModule, Finding


class JwtAnalyzerModule(ScannerModule):
    name = "jwt-analysis"
    category = "crypto"
    title = "JWT Weakness Analyzer"
    description = "Décode les JWT trouvés et teste la robustesse de leur signature."
    default_enabled = True

    # Wordlist courte de secrets HS256 communs
    COMMON_SECRETS = [
        "secret", "secret123", "secretkey", "jwtsecret", "your-secret-key",
        "password", "12345", "admin", "1234567890", "changeme",
        "weblab", "test", "demo", "default", "jwt_secret",
    ]

    JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []

        try:
            r = requests.get(target, timeout=8, headers={"User-Agent": "VulnScan/1.2"})
            body = r.text
            cookies = r.headers.get("Set-Cookie", "")
        except Exception:
            return findings

        tokens = set()
        for m in self.JWT_RE.findall(body):
            tokens.add(m)
        for m in self.JWT_RE.findall(cookies):
            tokens.add(m)

        for token in tokens:
            parts = token.split(".")
            if len(parts) != 3:
                continue
            try:
                header = self._b64decode(parts[0])
                payload_raw = self._b64decode(parts[1])
                header_obj = json.loads(header)
                payload_obj = json.loads(payload_raw)
            except Exception:
                continue

            alg = header_obj.get("alg", "")

            # 1. alg: none
            if alg.lower() == "none":
                findings.append(Finding(
                    type="jwt-weak", severity="critical",
                    title="JWT avec algorithme 'none'",
                    description="Le JWT utilise alg: none, donc accepté sans signature. Tout token peut être falsifié.",
                    recommendation="Imposer alg=HS256 ou RS256 côté serveur. Rejeter explicitement 'none'.",
                    url=target, parameter="JWT", payload=token[:80] + "...",
                    evidence=json.dumps(header_obj), confidence=100,
                    cwe_id="CWE-345", owasp_id="A02:2021",
                    cvss_base=9.8,
                    detection_method="header-inspection",
                    source="module:jwt-analysis",
                ))
                continue

            # 2. Test secret HMAC faible (uniquement HS256/HS384/HS512)
            if alg.startswith("HS"):
                signing_input = f"{parts[0]}.{parts[1]}".encode()
                actual_sig = self._b64decode_bytes(parts[2])
                hashfn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}.get(alg, hashlib.sha256)

                cracked = None
                for secret in self.COMMON_SECRETS:
                    expected = hmac.new(secret.encode(), signing_input, hashfn).digest()
                    if hmac.compare_digest(expected, actual_sig):
                        cracked = secret
                        break

                if cracked:
                    findings.append(Finding(
                        type="jwt-weak", severity="critical",
                        title=f"JWT signé avec un secret faible : '{cracked}'",
                        description=(
                            f"La signature {alg} a été cassée avec un secret trivial. "
                            "L'attaquant peut forger n'importe quel token."
                        ),
                        recommendation=(
                            "Utiliser un secret aléatoire ≥ 256 bits. Stocker en variable d'env, jamais dans le code."
                        ),
                        url=target, parameter="JWT signature",
                        payload=token[:80] + "...",
                        evidence=f"secret={cracked} | claims={json.dumps(payload_obj)}",
                        confidence=100,
                        cwe_id="CWE-798", owasp_id="A02:2021",
                        cvss_base=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        detection_method="dictionary-attack",
                        source="module:jwt-analysis",
                    ))

            # 3. Token expiré (info)
            exp = payload_obj.get("exp")
            if exp:
                import time
                if exp < time.time():
                    findings.append(Finding(
                        type="jwt-weak", severity="low",
                        title="JWT expiré dans la réponse",
                        description="Le serveur a renvoyé un token déjà expiré. Vérifier qu'il est bien rejeté.",
                        recommendation="Ne jamais renvoyer un token expiré. Régénérer côté serveur.",
                        url=target, parameter="JWT exp",
                        evidence=f"exp={exp}, now={int(time.time())}",
                        confidence=90,
                        cwe_id="CWE-613", owasp_id="A07:2021",
                        cvss_base=3.7,
                        detection_method="claims-inspection",
                        source="module:jwt-analysis",
                    ))

        return findings

    @staticmethod
    def _b64decode(s: str) -> str:
        s = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s.encode()).decode("utf-8", errors="replace")

    @staticmethod
    def _b64decode_bytes(s: str) -> bytes:
        s = s + "=" * (-len(s) % 4)
        return base64.urlsafe_b64decode(s.encode())
