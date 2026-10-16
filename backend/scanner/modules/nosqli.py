from __future__ import annotations
from typing import List, Dict, Any
import json
import secrets

from scanner.core.module_base import ScannerModule, Finding
from scanner.core import http
from scanner.payloads import get_payloads


class NoSqliModule(ScannerModule):
    name = "nosqli"
    category = "injection"
    title = "NoSQL Injection"
    description = "Injecte des opérateurs MongoDB dans les endpoints JSON découverts et compare le comportement à une baseline (bypass d'auth / fuite de données)."
    default_enabled = False

    MAX_ENDPOINTS = 5
    BODY_GROWTH_THRESHOLD = 1.2  # +20%

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        endpoints = (context.get("crawled") or {}).get("api_endpoints", [])[:self.MAX_ENDPOINTS]
        operator_payloads = [p["payload"] for p in get_payloads("nosqli", depth=context.get("depth"))]
        findings: List[Finding] = []
        for url in endpoints:
            findings.extend(self._test_endpoint(url, context, operator_payloads))
        return findings

    def _test_endpoint(self, url: str, context: Dict[str, Any], operator_payloads: List[Any]) -> List[Finding]:
        baseline_body = {"username": "vulnscan_probe", "password": "wrong_pw_" + secrets.token_hex(4)}
        r_base = http.post(url, context, json=baseline_body, timeout=8)
        if r_base is None or r_base.status_code in (404, 405, 415):
            return []
        baseline_status = r_base.status_code
        baseline_len = len(r_base.text)

        findings: List[Finding] = []
        for key in baseline_body.keys():
            for payload in operator_payloads:
                test_body = dict(baseline_body)
                test_body[key] = payload
                response, req_ev, resp_ev = http.post(url, context, json=test_body, capture=True, timeout=8)
                if response is None:
                    continue
                status_improved = (
                    baseline_status >= 400 and response.status_code < 400
                    and response.status_code != baseline_status
                )
                # body_grew doit signaler un vrai changement de comportement, pas juste du
                # bruit de taille entre deux status codes différents : un 401 à corps vide
                # suivi d'un 400 de validation ("password must be a string") est un rejet
                # correct, pas une fuite — on l'exclut en exigeant le MÊME status code que
                # la baseline (et un baseline_len > 0 pour éviter la dégénérescence "tout
                # corps non-vide est une croissance" quand la baseline est vide).
                body_grew = (
                    baseline_len > 0
                    and response.status_code == baseline_status
                    and len(response.text) > baseline_len * self.BODY_GROWTH_THRESHOLD
                )
                if status_improved or body_grew:
                    findings.append(Finding(
                        type="nosqli", severity="critical",
                        title=f"NoSQL Injection — clé '{key}'",
                        description=(
                            f"L'API {url} change de comportement quand la clé '{key}' reçoit un "
                            f"opérateur MongoDB ({json.dumps(payload)}) : statut {baseline_status}→"
                            f"{response.status_code}, taille {baseline_len}→{len(response.text)}."
                        ),
                        recommendation=(
                            "Typer et valider strictement les champs attendus (rejeter tout objet/opérateur "
                            "là où un scalaire est attendu). Utiliser une bibliothèque de validation de schéma."
                        ),
                        url=url, parameter=f"JSON body.{key}",
                        payload=json.dumps(test_body, ensure_ascii=False)[:200],
                        evidence=f"status {baseline_status}->{response.status_code}, taille {baseline_len}->{len(response.text)}",
                        confidence=80, cwe_id="CWE-943", owasp_id="A03:2021",
                        cvss_base=9.1,
                        detection_method="nosqli-behavioral-diff",
                        source="module:nosqli",
                        evidence_request=req_ev, evidence_response=resp_ev,
                    ))
                    break
        return findings
