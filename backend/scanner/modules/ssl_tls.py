"""
Module : SSL/TLS detail.

Analyse côté serveur de la qualité de la couche TLS de la cible :
  - Version min négociable (rejette TLS 1.0/1.1 → vuln)
  - Cipher suites supportées + détection des faibles (RC4, DES, EXPORT, NULL)
  - Validation du certificat (CN, SAN, expiration, issuer)
  - Protocoles obsolètes (SSLv2, SSLv3 → POODLE)

Utilise uniquement la stdlib (`ssl`, `socket`) — pas de dépendance externe.

Note : pour un audit TLS exhaustif (Heartbleed, FREAK, BEAST...) il faudrait
des outils dédiés comme testssl.sh / sslyze. Ce module fait l'essentiel.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse
import ssl
import socket
import datetime
import re

from scanner.core.module_base import ScannerModule, Finding


class SslTlsModule(ScannerModule):
    name = "ssl-tls"
    category = "crypto"
    title = "SSL/TLS Quality Audit"
    description = "Analyse la qualité TLS : versions, ciphers, certificat, expiration."
    default_enabled = True

    # Versions de protocole à tester (constants TLS dans Python 3.10+)
    OBSOLETE_VERSIONS = [
        (ssl.TLSVersion.SSLv3, "SSLv3", "critical", "Vulnérable à POODLE."),
        (ssl.TLSVersion.TLSv1, "TLSv1.0", "high", "Obsolète depuis 2020 (NIST, PCI-DSS)."),
        (ssl.TLSVersion.TLSv1_1, "TLSv1.1", "high", "Obsolète. Mauvais chiffrement disponible."),
    ]

    WEAK_CIPHER_KEYWORDS = ["RC4", "DES", "EXPORT", "NULL", "MD5", "ANON", "ADH"]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not target.startswith("https://"):
            return []
        parsed = urlparse(target)
        host = parsed.hostname
        port = parsed.port or 443
        if not host:
            return []

        findings: List[Finding] = []

        # 1. Récupérer le certificat + info de session
        try:
            cert_info = self._get_certificate_info(host, port)
        except Exception as e:
            return [Finding(
                type="tls", severity="medium",
                title="Erreur de handshake TLS",
                description=f"Impossible d'établir une connexion TLS : {e}",
                recommendation="Vérifier la configuration TLS du serveur.",
                url=target, parameter="TLS connection",
                evidence=str(e)[:200],
                confidence=80, cwe_id="CWE-326", owasp_id="A02:2021",
                cvss_base=5.3,
                detection_method="tls-handshake-failure",
                source="module:ssl-tls",
            )]

        # 2. Analyse du certificat (expiration, CN)
        findings.extend(self._analyze_cert(cert_info, target))

        # 3. Test des protocoles obsolètes
        findings.extend(self._test_obsolete_protocols(host, port, target))

        # 4. Test des ciphers faibles
        try:
            weak = self._check_weak_ciphers(host, port)
            if weak:
                findings.append(Finding(
                    type="tls", severity="medium",
                    title=f"Cipher suite faible négociable : {weak}",
                    description=f"Le serveur accepte un cipher faible : {weak}. Risque d'interception ou déchiffrement.",
                    recommendation=(
                        "Désactiver les ciphers contenant RC4, DES, EXPORT, NULL, MD5. "
                        "Configurer la liste recommandée par Mozilla SSL Config Generator (intermediate ou modern)."
                    ),
                    url=target, parameter="cipher suite",
                    evidence=weak, confidence=85, cwe_id="CWE-327", owasp_id="A02:2021",
                    cvss_base=6.5,
                    detection_method="weak-cipher-negotiation",
                    source="module:ssl-tls",
                ))
        except Exception:
            pass

        return findings

    # ============ helpers ============

    @staticmethod
    def _get_certificate_info(host: str, port: int) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()  # (name, protocol, secret_bits)
                version = ssock.version()
                return {"cert": cert, "cipher": cipher, "version": version}

    def _analyze_cert(self, info: Dict[str, Any], target: str) -> List[Finding]:
        findings: List[Finding] = []
        cert = info["cert"]
        if not cert:
            return findings

        # Expiration
        not_after = cert.get("notAfter")
        if not_after:
            try:
                expires = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expires - datetime.datetime.utcnow()).days
                if days_left < 0:
                    findings.append(Finding(
                        type="tls", severity="critical",
                        title=f"Certificat TLS EXPIRÉ ({-days_left} jours)",
                        description=f"Le certificat a expiré le {not_after}. Connexion non sécurisée.",
                        recommendation="Renouveler immédiatement le certificat.",
                        url=target, parameter="certificate notAfter",
                        evidence=not_after,
                        confidence=100, cwe_id="CWE-298", owasp_id="A02:2021",
                        cvss_base=7.4,
                        detection_method="cert-expiration-check",
                        source="module:ssl-tls",
                    ))
                elif days_left < 30:
                    findings.append(Finding(
                        type="tls", severity="medium",
                        title=f"Certificat TLS expire dans {days_left} jours",
                        description=f"Le certificat expire bientôt ({not_after}).",
                        recommendation="Planifier le renouvellement avant l'expiration.",
                        url=target, parameter="certificate notAfter",
                        evidence=not_after, confidence=100,
                        cwe_id="CWE-298", owasp_id="A02:2021",
                        cvss_base=4.3,
                        detection_method="cert-expiration-warning",
                        source="module:ssl-tls",
                    ))
            except Exception:
                pass

        # Issuer (auto-signé ?)
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        subject = dict(x[0] for x in cert.get("subject", ()))
        if issuer == subject:
            findings.append(Finding(
                type="tls", severity="high",
                title="Certificat auto-signé",
                description="Le certificat est auto-signé (issuer == subject). Non-fiable pour le grand public.",
                recommendation="Utiliser un certificat émis par une CA reconnue (Let's Encrypt, etc.).",
                url=target, parameter="certificate issuer",
                evidence=str(issuer)[:200], confidence=100,
                cwe_id="CWE-295", owasp_id="A02:2021",
                cvss_base=7.4,
                detection_method="cert-issuer-check",
                source="module:ssl-tls",
            ))

        return findings

    def _test_obsolete_protocols(self, host: str, port: int, target: str) -> List[Finding]:
        findings: List[Finding] = []
        for version, label, severity, why in self.OBSOLETE_VERSIONS:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = version
                ctx.maximum_version = version
                with socket.create_connection((host, port), timeout=4) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        # Si on arrive ici, le serveur accepte cette version
                        findings.append(Finding(
                            type="tls", severity=severity,
                            title=f"Protocole obsolète accepté : {label}",
                            description=f"Le serveur accepte {label} : {why}",
                            recommendation=f"Désactiver {label} côté serveur. Minimum TLS 1.2 (TLS 1.3 idéalement).",
                            url=target, parameter=f"protocol {label}",
                            evidence=ssock.version() or label,
                            confidence=100, cwe_id="CWE-326", owasp_id="A02:2021",
                            cvss_base=7.4 if severity == "critical" else 6.5,
                            detection_method="protocol-negotiation",
                            source="module:ssl-tls",
                        ))
            except (ssl.SSLError, ConnectionError, OSError, ValueError):
                pass  # version refusée : bonne nouvelle
        return findings

    def _check_weak_ciphers(self, host: str, port: int) -> str:
        """Tente d'établir la connexion avec une suite de ciphers faibles.
        Renvoie le nom du cipher négocié si l'un des faibles passe."""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # Liste OpenSSL incluant les ciphers faibles
            ctx.set_ciphers("ALL:eNULL:aNULL:RC4:DES:MD5:EXPORT:@SECLEVEL=0")
            with socket.create_connection((host, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cipher_name = ssock.cipher()[0] or ""
                    if any(kw in cipher_name for kw in self.WEAK_CIPHER_KEYWORDS):
                        return cipher_name
        except Exception:
            pass
        return ""
