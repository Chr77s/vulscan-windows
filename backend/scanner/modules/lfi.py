"""
Module : Local File Inclusion (LFI) / Path Traversal.

Test sur chaque paramètre GET :
    - payloads "../../../etc/passwd" (Linux) ou "..\\..\\..\\windows\\win.ini" (Windows)
    - payload "php://filter/convert.base64-encode/resource=index.php" (PHP)
puis vérifie si la réponse contient des signatures connues (root:x:0:0,
[boot loader], <?php, etc.).

Recommandation OWASP A03 / CWE-22.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding
from scanner.payloads import get_payloads


class LfiModule(ScannerModule):
    name = "lfi"
    category = "injection"
    title = "Local File Inclusion / Path Traversal"
    description = "Test de payloads de traversée de répertoires sur les paramètres GET."
    default_enabled = False  # actif

    SUSPECT_PARAMS = {"file", "page", "path", "include", "filename", "doc",
                      "view", "template", "module", "dir", "load", "read"}

    SIGNATURES_GENERIC = [
        (re.compile(r"root:[x*]:0:0", re.I),         "Fichier /etc/passwd"),
        (re.compile(r"\[fonts\]\s*\[extensions\]", re.I), "Fichier C:\\Windows\\win.ini"),
        (re.compile(r"\[boot loader\]", re.I),       "Fichier C:\\boot.ini"),
        (re.compile(r"warning:.*include\(", re.I),   "Erreur PHP include()"),
        (re.compile(r"failed to open stream", re.I), "Erreur PHP fopen()"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        payloads = [
            (p["payload"], p.get("signature", ""), p.get("category", "?"))
            for p in get_payloads("lfi", depth=context.get("depth"))
        ]
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))

        # 1. Détection passive : recherche d'erreurs include/require dans la réponse baseline
        try:
            r_base = http.get(target, context, timeout=8, headers={"User-Agent": "VulnScan/1.2"})
            if r_base is None:
                return findings
            for pattern, label in self.SIGNATURES_GENERIC:
                if pattern.search(r_base.text):
                    findings.append(Finding(
                        type="path-traversal", severity="high",
                        title="LFI : signature détectée dans la réponse baseline",
                        description=f"La réponse contient déjà : {label}. Indice fort d'une inclusion en cours.",
                        recommendation="Désactiver l'affichage des erreurs PHP. Utiliser une whitelist de fichiers.",
                        url=target, parameter="(body)",
                        evidence=pattern.search(r_base.text).group(0)[:200],
                        confidence=70,
                        cwe_id="CWE-22", owasp_id="A03:2021",
                        cvss_base=7.5,
                        detection_method="passive-signature-scan",
                        source="module:lfi",
                    ))
                    break
        except Exception:
            return findings

        # 2. Détection semi-active : test payloads sur params suspects
        for param_name in params:
            if param_name.lower() not in self.SUSPECT_PARAMS:
                continue

            for payload, sig_pattern, os_label in payloads:
                # signature vide (php://input) : re.search("", ...) matcherait toujours
                if not sig_pattern:
                    continue
                try:
                    new_params = dict(params)
                    new_params[param_name] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    r, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8,
                                                   headers={"User-Agent": "VulnScan/1.2"})
                    if r is None:
                        continue
                    if re.search(sig_pattern, r.text):
                        findings.append(Finding(
                            type="path-traversal", severity="critical",
                            title=f"LFI confirmée ({os_label})",
                            description=(
                                f"Paramètre '{param_name}' permet d'inclure le fichier {payload}. "
                                f"Signature {os_label} détectée dans la réponse."
                            ),
                            recommendation=(
                                "Utiliser une whitelist stricte de fichiers acceptés (ex: array_key_exists). "
                                "Ne jamais concaténer une entrée utilisateur dans un include/require."
                            ),
                            url=target, parameter=param_name,
                            payload=payload,
                            evidence=r.text[:300].replace("\n", " "),
                            confidence=95,
                            cwe_id="CWE-22", owasp_id="A03:2021",
                            cvss_base=8.6,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                            detection_method="payload-injection",
                            source="module:lfi",
                            evidence_request=req_ev, evidence_response=resp_ev,
                        ))
                        break  # une seule preuve par param suffit
                except Exception:
                    continue

        return findings
