"""
Module : JSON Body Fuzzer (API endpoints).

Pour les endpoints détectés par le crawler (URLs en /api/, /v1/, /v2/ ou
content-type application/json), envoie des POST avec un body JSON contenant
des payloads dans chaque clé.

Stratégie :
  - Détection des endpoints API
  - Construit un body JSON template avec valeurs neutres
  - Pour chaque clé, remplace par payload XSS/SQLi
  - Vérifie reflet du marqueur, erreurs SQL, ou diff de réponse

⚠️ Module actif : envoie de vrais POST application/json.
"""
from __future__ import annotations
from typing import List, Dict, Any
import requests
import secrets
import json
import re

from scanner.core.module_base import ScannerModule, Finding


class JsonFuzzerModule(ScannerModule):
    name = "json-fuzzer"
    category = "injection"
    title = "JSON API Body Fuzzer"
    description = "Fuzz les endpoints API JSON (POST application/json) avec XSS/SQLi/NoSQLi."
    default_enabled = False

    MAX_ENDPOINTS = 5
    API_PATTERN = re.compile(r"/(?:api|v\d+|rest|graphql|json)/", re.I)

    # Payloads adaptés au JSON
    PAYLOADS = [
        {"value": "<svg onload=alert({MARK})>",  "type": "xss",    "key_signal": "{MARK}"},
        {"value": "' OR '1'='1",                  "type": "sqli",   "expect_error": True},
        {"value": {"$gt": ""},                    "type": "nosqli", "key_signal": None, "is_obj": True},
        {"value": "../../../etc/passwd",          "type": "lfi",    "key_signal": "root:[x*]:0:0"},
    ]

    SQL_ERROR = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"sqlite3?\.operationalerror", re.I),
        re.compile(r"mongoose|mongodb", re.I),  # NoSQL hint
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        endpoints = self._find_api_endpoints(target, context)
        if not endpoints:
            return []

        findings: List[Finding] = []
        for ep in endpoints[:self.MAX_ENDPOINTS]:
            findings.extend(self._fuzz_endpoint(ep))
        return findings

    def _find_api_endpoints(self, target: str, context: Dict[str, Any]) -> List[str]:
        urls = set()
        # Si target lui-même paraît être une API
        if self.API_PATTERN.search(target):
            urls.add(target)
        # Endpoints depuis le crawler
        crawled = (context.get("crawled") or {})
        for ep in crawled.get("api_endpoints", []):
            urls.add(ep)
        for u in crawled.get("urls", []):
            if self.API_PATTERN.search(u):
                urls.add(u)
        return sorted(urls)

    def _fuzz_endpoint(self, url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Baseline JSON minimal — on tente avec un payload neutre pour voir si l'API accepte
        baseline_body = {"id": 1, "name": "test", "value": "baseline"}
        try:
            r_base = requests.post(url, json=baseline_body, timeout=8,
                                   headers={"User-Agent": "VulnScan/1.3"})
            if r_base.status_code in (404, 405, 415):
                return []  # endpoint pas valide / méthode pas supportée
        except Exception:
            return []

        body_base = r_base.text

        for key in baseline_body.keys():
            for payload_def in self.PAYLOADS:
                mark = secrets.token_hex(3)
                val = payload_def["value"]
                if isinstance(val, str):
                    val_str = val.replace("{MARK}", mark)
                else:
                    val_str = val  # objet (NoSQLi)

                test_body = dict(baseline_body)
                test_body[key] = val_str
                try:
                    r = requests.post(url, json=test_body, timeout=8,
                                      headers={"User-Agent": "VulnScan/1.3"})
                    body = r.text
                except Exception:
                    continue

                # 1. XSS — marqueur reflété
                if payload_def["type"] == "xss" and mark in body:
                    findings.append(Finding(
                        type="xss", severity="high",
                        title=f"XSS via JSON API — clé '{key}'",
                        description=(
                            f"L'API à {url} reflète la valeur de la clé '{key}' du body JSON. "
                            f"Marqueur '{mark}' détecté dans la réponse."
                        ),
                        recommendation="Échapper côté serveur ou définir Content-Type: application/json + CSP.",
                        url=url, parameter=f"JSON body.{key}",
                        payload=json.dumps(test_body, ensure_ascii=False)[:200],
                        evidence=f"Marqueur '{mark}' reflété",
                        confidence=90, cwe_id="CWE-79", owasp_id="A03:2021",
                        cvss_base=6.1,
                        detection_method="json-fuzz-reflection",
                        source="module:json-fuzzer",
                    ))
                    break

                # 2. SQLi / NoSQLi — signatures d'erreur
                if payload_def["type"] in ("sqli", "nosqli"):
                    for sig in self.SQL_ERROR:
                        if sig.search(body):
                            findings.append(Finding(
                                type=payload_def["type"], severity="critical",
                                title=f"{payload_def['type'].upper()} via JSON API — clé '{key}'",
                                description=(
                                    f"L'API révèle une erreur de base de données après injection "
                                    f"dans la clé '{key}'. {sig.search(body).group(0)[:100]}"
                                ),
                                recommendation="Utiliser des requêtes paramétrées (SQL) ou opérateurs typés (NoSQL).",
                                url=url, parameter=f"JSON body.{key}",
                                payload=json.dumps(test_body, ensure_ascii=False)[:200],
                                evidence=sig.search(body).group(0)[:200],
                                confidence=90, cwe_id="CWE-89", owasp_id="A03:2021",
                                cvss_base=9.8,
                                detection_method="json-fuzz-error-signature",
                                source="module:json-fuzzer",
                            ))
                            break

                # 3. LFI
                if payload_def["type"] == "lfi":
                    sig = re.search(payload_def["key_signal"], body)
                    if sig:
                        findings.append(Finding(
                            type="path-traversal", severity="critical",
                            title=f"LFI via JSON API — clé '{key}'",
                            description=f"L'API permet d'inclure /etc/passwd via la clé '{key}'.",
                            recommendation="Whitelist les fichiers acceptés. Ne jamais include un input.",
                            url=url, parameter=f"JSON body.{key}",
                            payload=json.dumps(test_body, ensure_ascii=False)[:200],
                            evidence=sig.group(0)[:200],
                            confidence=95, cwe_id="CWE-22", owasp_id="A03:2021",
                            cvss_base=9.8,
                            detection_method="json-fuzz-lfi-signature",
                            source="module:json-fuzzer",
                        ))
                        break

        return findings
