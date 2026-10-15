"""
Module : Server-Side Request Forgery (SSRF).

Détection prudente — on ne fait PAS taper d'IP interne réelle :
  - On repère les paramètres qui ressemblent à des URLs (url=, src=, redirect=, proxy=)
  - On envoie un payload `http://127.0.0.1:80` (loopback)
    Si la réponse change significativement ET ne contient PAS d'erreur DNS,
    c'est un fort signal de SSRF.
  - Bonus : on teste `file:///etc/hostname` pour valider SSRF→LFI.

OWASP A10:2021 / CWE-918.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import difflib
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding
from scanner.core.oob import OOBCanary
from scanner.payloads import get_payloads


class SsrfModule(ScannerModule):
    name = "ssrf"
    category = "injection"
    title = "Server-Side Request Forgery"
    description = "Test SSRF sur paramètres URL-like avec payloads loopback et file://"
    default_enabled = False  # actif

    URL_LIKE_PARAMS = {"url", "uri", "src", "source", "target", "dest", "redirect",
                       "proxy", "fetch", "callback", "webhook", "endpoint", "host"}

    ERROR_SIGNATURES = [
        re.compile(r"connection refused", re.I),
        re.compile(r"getaddrinfo failed", re.I),
        re.compile(r"could not resolve host", re.I),
        re.compile(r"connect ECONNREFUSED", re.I),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        payloads = [
            (p["payload"], p.get("description", "?"))
            for p in get_payloads("ssrf", depth=context.get("depth"))
        ]
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))

        try:
            r_base = http.get(target, context, timeout=8, headers={"User-Agent": "VulnScan/1.2"})
            if r_base is None:
                return findings
            body_base = r_base.text
        except Exception:
            return findings

        # === Détection BLIND SSRF via OOB Collaborator ===
        # Pour chaque paramètre URL-like, on envoie l'URL du canary.
        # Si le canary est hit dans les 4s, c'est un SSRF confirmé sans retour visible.
        for param_name in params:
            if param_name.lower() not in self.URL_LIKE_PARAMS and not re.match(r"^https?://", params[param_name]):
                continue
            canary = OOBCanary.new()
            try:
                new_params = dict(params)
                new_params[param_name] = canary.url
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                http.get(test_url, context, timeout=8, headers={"User-Agent": "VulnScan/1.2"})
            except Exception:
                continue
            if canary.wait_for_hit(timeout=4):
                hit = canary.hits()[0] if canary.hits() else {}
                findings.append(Finding(
                    type="ssrf", severity="critical",
                    title="Blind SSRF confirmé via OOB",
                    description=(
                        f"Le serveur a effectivement fait une requête vers le canary "
                        f"{canary.url} (méthode {hit.get('method', '?')}). "
                        "C'est un SSRF exploitable même sans retour visible dans la réponse."
                    ),
                    recommendation=(
                        "Whitelist des hôtes autorisés côté serveur. Bloquer les IPs internes "
                        "(127/8, 10/8, 192.168/16, 169.254/16). Désactiver les schémas dangereux."
                    ),
                    url=target, parameter=param_name,
                    payload=canary.url,
                    evidence=f"Hit OOB : {hit.get('method')} from {hit.get('ip')} UA={hit.get('user_agent', '')[:60]}",
                    confidence=100, cwe_id="CWE-918", owasp_id="A10:2021",
                    cvss_base=9.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                    detection_method="oob-canary",
                    source="module:ssrf",
                ))
                break  # une confirmation suffit

        for param_name, base_value in params.items():
            # Heuristique 1 : nom suggestif
            looks_url_like = param_name.lower() in self.URL_LIKE_PARAMS
            # Heuristique 2 : valeur déjà URL-like
            base_is_url = bool(re.match(r"^https?://", base_value))
            if not (looks_url_like or base_is_url):
                continue

            for payload, label in payloads:
                try:
                    new_params = dict(params)
                    new_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    r, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8,
                                                   headers={"User-Agent": "VulnScan/1.2"})
                    if r is None:
                        continue
                    body = r.text

                    # Si erreur DNS/conn refused → bonne nouvelle (le serveur a essayé)
                    # mais ce n'est PAS une exfil. On le signale en medium.
                    for sig in self.ERROR_SIGNATURES:
                        if sig.search(body):
                            findings.append(Finding(
                                type="ssrf", severity="medium",
                                title="SSRF probable — erreur de connexion exfiltrée",
                                description=(
                                    f"Le serveur a tenté de joindre {payload} et renvoyé une erreur de connexion. "
                                    "Cela confirme qu'il fait des requêtes selon le paramètre."
                                ),
                                recommendation=(
                                    "Imposer une whitelist d'hôtes/URLs autorisés côté serveur. "
                                    "Bloquer les IPs internes (169.254/16, 10/8, 192.168/16, 127/8)."
                                ),
                                url=target, parameter=param_name,
                                payload=payload,
                                evidence=sig.search(body).group(0),
                                confidence=80,
                                cwe_id="CWE-918", owasp_id="A10:2021",
                                cvss_base=8.6,
                                detection_method="error-disclosure",
                                source="module:ssrf",
                                evidence_request=req_ev, evidence_response=resp_ev,
                            ))
                            break
                    else:
                        # Diff sur la réponse — réponse très différente = succès SSRF probable
                        ratio = difflib.SequenceMatcher(None, body_base, body).ratio()
                        if ratio < 0.3 and len(body) > 100:
                            findings.append(Finding(
                                type="ssrf", severity="high",
                                title=f"SSRF probable ({label})",
                                description=(
                                    f"Paramètre '{param_name}' modifié vers {payload} change radicalement la "
                                    f"réponse (similarité {ratio:.2f}). Indice de SSRF exploitable."
                                ),
                                recommendation=(
                                    "Valider l'URL côté serveur (whitelist d'hôtes). "
                                    "Ne jamais déréférencer une URL utilisateur sans contrôle."
                                ),
                                url=target, parameter=param_name,
                                payload=payload,
                                evidence=body[:200].replace("\n", " "),
                                confidence=int(70 + (1 - ratio) * 25),
                                cwe_id="CWE-918", owasp_id="A10:2021",
                                cvss_base=8.6,
                                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",
                                detection_method="response-diff",
                                source="module:ssrf",
                                evidence_request=req_ev, evidence_response=resp_ev,
                            ))
                            break
                except Exception:
                    continue
        return findings
