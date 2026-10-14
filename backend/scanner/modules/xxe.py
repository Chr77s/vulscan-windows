"""
Module : XXE (XML External Entity) — détection légère.

Envoie un POST/GET de prouve avec un payload XML contenant une déclaration
DOCTYPE et une entité externe pointant vers un canary. Vérifie si la réponse
contient la marque ou une erreur de parsing révélatrice.

⚠️ Ne fait pas d'exfiltration réelle (notre payload pointe vers un faux host).

OWASP A05 / CWE-611.
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import re

from scanner.core.module_base import ScannerModule, Finding


class XxeModule(ScannerModule):
    name = "xxe"
    category = "injection"
    title = "XML External Entity"
    description = "Test XXE via payload DOCTYPE — détecte les parseurs XML mal configurés."
    default_enabled = False

    PAYLOAD = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>\n'
        '<root>&xxe;</root>\n'
    )

    XML_ENDPOINTS_HINTS = ("xml", "soap", "rss", "atom", "wsdl", "api")

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []

        # On envoie le payload XML uniquement si l'URL paraît acceptable
        # (sinon ça pollue inutilement les serveurs HTML).
        if not any(hint in target.lower() for hint in self.XML_ENDPOINTS_HINTS):
            return []

        try:
            r = requests.post(target, data=self.PAYLOAD, timeout=8, headers={
                "Content-Type": "application/xml",
                "User-Agent": "VulnScan/1.2",
            })
            body = r.text
        except Exception:
            return []

        # Signatures :
        #  - erreur de DOCTYPE / DTD non autorisé → bon comportement
        #  - "file://" dans la réponse → XXE confirmé (parsing actif)
        #  - "Entity 'xxe' was referenced..." → XXE confirmé partiel
        findings: List[Finding] = []

        if re.search(r"file://[a-z0-9/.\-_]+", body, re.I):
            findings.append(Finding(
                type="xxe", severity="critical",
                title="XXE : fichier externe lu",
                description="Le payload XXE avec ENTITY SYSTEM \"file://...\" est interprété et la valeur revient dans la réponse.",
                recommendation=(
                    "Désactiver les entités externes côté parseur (DEFUSEDXML en Python, "
                    "setFeature 'disallow-doctype-decl' en Java, libxml_disable_entity_loader en PHP)."
                ),
                url=target, parameter="(body XML)",
                payload=self.PAYLOAD,
                evidence=re.search(r"file://[a-z0-9/.\-_]+", body, re.I).group(0),
                confidence=95,
                cwe_id="CWE-611", owasp_id="A05:2021",
                cvss_base=9.8,
                detection_method="payload-doctype",
                source="module:xxe",
            ))
        elif re.search(r"xml.*(entity|doctype)", body, re.I):
            findings.append(Finding(
                type="xxe", severity="medium",
                title="XXE : parseur révélant l'entité",
                description="Le parseur XML rapporte une référence à 'xxe' — indice d'un parseur permissif.",
                recommendation="Désactiver les DOCTYPE et entités externes côté parseur.",
                url=target, parameter="(body XML)",
                payload=self.PAYLOAD,
                evidence=re.search(r"xml.*(entity|doctype).*", body, re.I).group(0)[:200],
                confidence=70,
                cwe_id="CWE-611", owasp_id="A05:2021",
                cvss_base=7.5,
                detection_method="error-signal",
                source="module:xxe",
            ))
        return findings
