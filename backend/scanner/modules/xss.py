"""
Module : détection XSS reflété (semi-actif).

Stratégie :
  1. Pour chaque paramètre GET, injecte un marqueur unique non-malveillant
     (string aléatoire) et vérifie s'il est reflété tel quel dans la réponse.
  2. Si reflété : test des contextes (HTML, attribut, JS, URL) et propose
     les payloads adaptés.

Le payload réel n'est pas exécuté — on observe juste si le marqueur ressort,
ce qui ne casse rien et reste défensif.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import secrets
import re

from scanner.core import http
from scanner.core.matchers import HttpResult, Matcher, evaluate
from scanner.core.module_base import ScannerModule, Finding
from scanner.payloads import get_payloads


class XssModule(ScannerModule):
    name = "xss"
    category = "injection"
    title = "Cross-Site Scripting (Reflected)"
    description = "Détecte les paramètres GET réfléchis dans la réponse — base d'une XSS reflétée."
    default_enabled = False  # Module actif

    _CONTEXTS = ("html_context", "attribute_context", "js_context", "url_context", "svg_context", "img_context")

    def _payload_catalog(self, depth):
        out = {}
        for ctx in self._CONTEXTS:
            items = get_payloads("xss", category=ctx, depth=depth)
            if items:
                # Seule l'entrée basic (la 1re) est utilisée : les entrées extended/aggressive
                # de xss.json ne sont jamais envoyées, quelle que soit la valeur de `depth`.
                out[ctx] = items[0]["payload"]
        return out

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))
        if not params:
            return []

        depth = context.get("depth")
        catalog = self._payload_catalog(depth)
        for param_name, base_value in params.items():
            marker = "vsx" + secrets.token_hex(4)  # marqueur unique
            test_params = dict(params)
            test_params[param_name] = marker
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

            try:
                response, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8,
                                                       headers={"User-Agent": "VulnScan/1.2"})
                if response is None:
                    continue
                body = response.text
            except Exception:
                continue

            result = HttpResult(status=response.status_code, headers=dict(response.headers), body=body)
            if not evaluate([Matcher(type="word", part="body", words=[marker])], "and", result):
                continue  # pas réfléchi

            # Détecter le contexte du reflet
            contexts = self._detect_contexts(body, marker)
            payloads = [catalog[c] for c in contexts if c in catalog]

            description = (
                f"Le paramètre '{param_name}' est réfléchi tel quel dans la réponse "
                f"({len(contexts)} contexte(s) détecté(s) : {', '.join(contexts) or 'html'}). "
                "Un payload de script pourrait être exécuté."
            )
            recommendation = (
                "Encoder la sortie selon le contexte (HTMLEntity, attribute, JS, URL). "
                "Mettre en place une CSP stricte. Côté serveur : DOMPurify, htmlspecialchars(), etc."
            )

            confirmed = None
            for ctx in contexts:
                confirmed = self._try_confirm(parsed, params, param_name, ctx, depth, context)
                if confirmed:
                    break

            if confirmed:
                confirmed_payload, c_req_ev, c_resp_ev = confirmed
                findings.append(Finding(
                    type="xss", severity="high",
                    title="Reflected XSS — Parameter Reflection",
                    description=description,
                    recommendation=recommendation,
                    url=target, parameter=param_name,
                    payload=confirmed_payload,
                    evidence=f"Payload reflété sans échappement : {confirmed_payload[:150]}",
                    confidence=95,
                    cwe_id="CWE-79", owasp_id="A03:2021",
                    cvss_base=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    detection_method="payload-confirmed-unescaped",
                    source="module:xss",
                    evidence_request=c_req_ev, evidence_response=c_resp_ev,
                ))
            else:
                findings.append(Finding(
                    type="xss", severity="high",
                    title="Reflected XSS — Parameter Reflection",
                    description=description,
                    recommendation=recommendation,
                    url=target, parameter=param_name,
                    payload=payloads[0] if payloads else catalog.get("html_context", "<script>alert(1)</script>"),
                    evidence=self._extract_context(body, marker),
                    confidence=85,
                    cwe_id="CWE-79", owasp_id="A03:2021",
                    cvss_base=6.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    detection_method="reflection-marker",
                    source="module:xss",
                    evidence_request=req_ev, evidence_response=resp_ev,
                ))
        return findings

    def _try_confirm(self, parsed, original_params, param_name, ctx, depth, context):
        """Essaie chaque payload du catalogue (filtré par depth) pour ce contexte, et retourne
        (payload, req_ev, resp_ev) dès que l'un d'eux reflète verbatim et sans échappement."""
        for item in get_payloads("xss", category=ctx, depth=depth):
            payload_value = item["payload"]
            try:
                test_params = dict(original_params)
                test_params[param_name] = payload_value
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                response, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8,
                                                       headers={"User-Agent": "VulnScan/1.2"})
                if response is None:
                    continue
                if payload_value in response.text and self._breaks_context(response.text, payload_value):
                    return payload_value, req_ev, resp_ev
            except Exception:
                continue
        return None

    @staticmethod
    def _breaks_context(body: str, payload_value: str) -> bool:
        """Une réflexion verbatim ne prouve rien si le payload reste emprisonné dans l'attribut
        ou la chaîne JS qui le contenait déjà : un serveur qui échappe correctement peut quand même
        reflèter tel quel un payload qui ne contient aucun caractère à échapper (ex. un payload
        attribute_context sans guillemet). On vérifie que le guillemet ouvrant juste avant le payload
        est bien présent DANS le payload (donc qu'il casse réellement l'attribut/la chaîne) ;
        s'il n'y a pas de guillemet ouvrant avant (html/svg/img/url context), rien à vérifier de plus."""
        idx = body.find(payload_value)
        if idx == -1:
            return False
        before = body[max(0, idx - 80):idx]
        quote_match = re.search(r'=\s*(["\'])$', before)
        if not quote_match:
            return True
        quote = quote_match.group(1)
        return quote in payload_value

    @staticmethod
    def _detect_contexts(body: str, marker: str) -> List[str]:
        """Identifie dans quel contexte HTML le marqueur apparaît."""
        contexts = []
        idx = body.find(marker)
        if idx == -1:
            return contexts
        before = body[max(0, idx - 80):idx]
        after  = body[idx:idx + 80]

        # JS context
        if re.search(r"<script[^>]*>[^<]*$", before, re.I) or "var " in before[-30:]:
            contexts.append("js_context")
        # Attribute context (entre " ou ')
        elif re.search(r'=["\'][^"\']*$', before):
            contexts.append("attribute_context")
        # URL context (href, src)
        elif re.search(r'(href|src|action)\s*=\s*["\']?[^"\'>]*$', before, re.I):
            contexts.append("url_context")
        # HTML context (cas par défaut)
        else:
            contexts.append("html_context")
        return contexts

    @staticmethod
    def _extract_context(body: str, marker: str, span: int = 100) -> str:
        idx = body.find(marker)
        if idx == -1:
            return ""
        return body[max(0, idx - span):idx + len(marker) + span].replace("\n", " ").strip()
