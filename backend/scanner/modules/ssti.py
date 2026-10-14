from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

from scanner.core.module_base import ScannerModule, Finding
from scanner.core import http


class SstiModule(ScannerModule):
    name = "ssti"
    category = "injection"
    title = "Server-Side Template Injection (SSTI)"
    description = "Injecte des expressions de calcul dans les paramètres GET pour détecter l'évaluation côté serveur (Jinja2/Twig/Freemarker/Thymeleaf)."
    default_enabled = False

    SUSPECT_PARAMS = {"name", "search", "q", "query", "page", "template", "view",
                      "title", "message", "comment", "text", "content"}

    PROBES = [
        ("{{7*7}}", "Jinja2/Twig", "49"),
        ("${7*7}",  "Freemarker/Velocity", "49"),
        ("#{7*7}",  "Thymeleaf (SpEL)", "49"),
        ("*{7*7}",  "Thymeleaf (alt)", "49"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))
        if not params:
            return []

        findings: List[Finding] = []
        r_base = http.get(target, context, timeout=8)
        if r_base is None:
            return []
        baseline_body = r_base.text

        for param_name, base_value in params.items():
            if param_name.lower() not in self.SUSPECT_PARAMS:
                continue
            for payload, engine, expected in self.PROBES:
                new_params = dict(params)
                new_params[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                response, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8)
                if response is None:
                    continue
                if expected in response.text and expected not in baseline_body:
                    findings.append(Finding(
                        type="ssti", severity="critical",
                        title=f"SSTI confirmée ({engine})",
                        description=(
                            f"Le paramètre '{param_name}' évalue '{payload}' côté serveur : "
                            f"'{expected}' apparaît dans la réponse et était absent de la baseline."
                        ),
                        recommendation=(
                            "Ne jamais passer d'entrée utilisateur directement à un moteur de template. "
                            "Utiliser le sandboxing du moteur (Jinja2 SandboxedEnvironment) ou séparer "
                            "strictement template et données."
                        ),
                        url=target, parameter=param_name, payload=payload,
                        evidence=f"'{expected}' obtenu, absent de la baseline",
                        confidence=90, cwe_id="CWE-1336", owasp_id="A03:2021",
                        cvss_base=9.8,
                        detection_method="ssti-arithmetic-probe",
                        source="module:ssti",
                        evidence_request=req_ev, evidence_response=resp_ev,
                    ))
                    break
        return findings
