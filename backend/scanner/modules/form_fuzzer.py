"""
Module : Form Fuzzer (POST body injection).

Pour chaque formulaire découvert par le crawler :
  - Génère un baseline (POST avec valeurs neutres)
  - Pour chaque champ texte/email/url/textarea, injecte un payload XSS, SQLi, LFI
  - Détecte les vulnérabilités via :
      * Reflet d'un marqueur unique (XSS)
      * Signature d'erreur SQL dans la réponse (SQLi)
      * Signature /etc/passwd ou similaire (LFI)
      * Différence radicale de réponse vs baseline (blind)

⚠️ Ce module envoie de **vrais POST**. Il évite :
  - Les forms qui contiennent un champ "password" (risque de lockout)
  - Les forms dont l'action contient "logout", "delete", "destroy"
  - Plus de 5 forms par scan (rate-limit)
"""
from __future__ import annotations
from typing import List, Dict, Any
import secrets
import difflib
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding


class FormFuzzerModule(ScannerModule):
    name = "form-fuzzer"
    category = "injection"
    title = "Form Body Fuzzer (POST)"
    description = "Fuzz les formulaires découverts (POST body) avec payloads XSS/SQLi/LFI."
    default_enabled = False  # actif — peut créer des entrées DB

    MAX_FORMS = 5
    DANGEROUS_ACTION_RE = re.compile(r"(logout|delete|destroy|remove|drop|wipe)", re.I)
    DANGEROUS_FIELD_RE  = re.compile(r"(password|passwd|pwd|confirm)", re.I)

    # Payloads minimalistes pour ce module (les catalogues sont aussi disponibles)
    PAYLOADS = [
        {"value": "<svg onload=alert({MARK})>",   "type": "xss",  "signature_in_response": "<svg onload=alert({MARK})>"},
        {"value": "' OR '1'='1",                   "type": "sqli", "signature_in_response": None, "expects_error": True},
        {"value": "'\"<>{MARK}",                   "type": "xss",  "signature_in_response": "'\"<>{MARK}"},
        {"value": "../../../etc/passwd",           "type": "lfi",  "signature_in_response": "root:[x*]:0:0"},
    ]

    SQL_ERROR_PATTERNS = [
        re.compile(r"you have an error in your sql syntax", re.I),
        re.compile(r"warning.*mysql_", re.I),
        re.compile(r"unclosed quotation mark", re.I),
        re.compile(r"sqlite3?\.operationalerror", re.I),
        re.compile(r"ora-\d{5}", re.I),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        forms = (context.get("crawled") or {}).get("forms", [])
        if not forms:
            return []

        # Filtre les forms dangereux
        safe_forms = []
        for f in forms[:self.MAX_FORMS * 2]:
            if self.DANGEROUS_ACTION_RE.search(f.get("action", "")):
                continue
            if any(self.DANGEROUS_FIELD_RE.search(field["name"]) for field in f["fields"]):
                continue
            safe_forms.append(f)
            if len(safe_forms) >= self.MAX_FORMS:
                break

        if not safe_forms:
            return []

        findings: List[Finding] = []
        for form in safe_forms:
            findings.extend(self._fuzz_form(form, context))
        return findings

    def _fuzz_form(self, form: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        action = form["action"]
        method = form["method"]
        fields = form["fields"]
        if not fields:
            return []

        # Construire un baseline avec valeurs neutres
        baseline_data = {f["name"]: f.get("value") or "test" for f in fields}
        try:
            baseline = self._send(action, method, baseline_data, context)
            if baseline is None:
                return []
        except Exception:
            return []

        # Pour chaque champ texte, fuzz avec chaque payload
        target_fields = [f for f in fields if f["type"] in ("text", "email", "url", "search", "tel", "textarea", "hidden")]
        if not target_fields:
            return []

        for field in target_fields:
            for payload_def in self.PAYLOADS:
                mark = secrets.token_hex(3)  # marqueur unique pour ce test
                payload_str = payload_def["value"].replace("{MARK}", mark)

                test_data = dict(baseline_data)
                test_data[field["name"]] = payload_str

                try:
                    r = self._send(action, method, test_data, context)
                    if r is None:
                        continue
                except Exception:
                    continue

                # 1. XSS — chercher le marqueur reflété
                if payload_def.get("signature_in_response"):
                    expected = payload_def["signature_in_response"].replace("{MARK}", mark)
                    if expected in r:
                        findings.append(self._build_xss(action, method, field, payload_str, r, mark))
                        break  # une preuve suffit pour ce champ

                # 2. SQLi — signatures d'erreur
                if payload_def.get("expects_error"):
                    for sig in self.SQL_ERROR_PATTERNS:
                        if sig.search(r):
                            findings.append(self._build_sqli(action, method, field, payload_str, sig.search(r).group(0)))
                            break

                # 3. LFI — signatures de fichier
                if payload_def["type"] == "lfi":
                    sig = re.search(payload_def["signature_in_response"], r)
                    if sig:
                        findings.append(self._build_lfi(action, method, field, payload_str, sig.group(0)))
                        break

                # 4. Blind — diff de réponse
                ratio = difflib.SequenceMatcher(None, baseline, r).ratio()
                if ratio < 0.3 and len(r) > 100 and payload_def["type"] == "sqli":
                    findings.append(self._build_blind_sqli(action, method, field, payload_str, ratio))
                    break

        return findings

    @staticmethod
    def _send(action: str, method: str, data: dict, context: Dict[str, Any]) -> str | None:
        try:
            if method.upper() == "POST":
                r = http.post(action, context, data=data, timeout=8,
                              headers={"User-Agent": "VulnScan/1.3"})
            else:
                r = http.get(action, context, params=data, timeout=8,
                             headers={"User-Agent": "VulnScan/1.3"})
            return r.text if r is not None else None
        except Exception:
            return None

    @staticmethod
    def _build_xss(action, method, field, payload, body, mark):
        return Finding(
            type="xss", severity="high",
            title=f"Stored/Reflected XSS via formulaire — champ '{field['name']}'",
            description=(
                f"Le payload injecté dans le champ '{field['name']}' (POST {action}) "
                f"est reflété tel quel dans la réponse. Confirmé par marqueur unique '{mark}'."
            ),
            recommendation=(
                "Échapper la sortie côté serveur (htmlspecialchars, DOMPurify) et "
                "définir une CSP stricte sans 'unsafe-inline'."
            ),
            url=action, parameter=field["name"], payload=payload,
            evidence=f"Marqueur '{mark}' reflété dans la réponse",
            confidence=90, cwe_id="CWE-79", owasp_id="A03:2021",
            cvss_base=6.1, cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            detection_method="form-fuzz-reflection",
            source="module:form-fuzzer",
        )

    @staticmethod
    def _build_sqli(action, method, field, payload, evidence):
        return Finding(
            type="sqli", severity="critical",
            title=f"SQL Injection via formulaire — champ '{field['name']}'",
            description=(
                f"Le serveur révèle une erreur SQL après injection dans '{field['name']}' "
                f"(POST {action}). Preuve : {evidence[:120]}"
            ),
            recommendation="Utiliser des requêtes paramétrées (prepared statements) sur ce champ.",
            url=action, parameter=field["name"], payload=payload,
            evidence=evidence[:200],
            confidence=90, cwe_id="CWE-89", owasp_id="A03:2021",
            cvss_base=9.8,
            detection_method="form-fuzz-error-signature",
            source="module:form-fuzzer",
        )

    @staticmethod
    def _build_blind_sqli(action, method, field, payload, ratio):
        return Finding(
            type="sqli", severity="high",
            title=f"Blind SQLi probable via formulaire — champ '{field['name']}'",
            description=(
                f"Le champ '{field['name']}' produit une réponse radicalement différente "
                f"de la baseline (similarité {ratio:.2f}) après injection booléenne."
            ),
            recommendation="Utiliser des requêtes paramétrées et logger les tentatives suspectes.",
            url=action, parameter=field["name"], payload=payload,
            evidence=f"sim={ratio:.2f}",
            confidence=70, cwe_id="CWE-89", owasp_id="A03:2021",
            cvss_base=8.6,
            detection_method="form-fuzz-blind-diff",
            source="module:form-fuzzer",
        )

    @staticmethod
    def _build_lfi(action, method, field, payload, sig):
        return Finding(
            type="path-traversal", severity="critical",
            title=f"LFI via formulaire — champ '{field['name']}'",
            description=f"Inclusion de /etc/passwd via le champ '{field['name']}'. Signature: {sig}",
            recommendation="Whitelist les valeurs de fichier acceptées. Ne jamais concaténer une entrée dans include/require.",
            url=action, parameter=field["name"], payload=payload,
            evidence=sig,
            confidence=95, cwe_id="CWE-22", owasp_id="A03:2021",
            cvss_base=8.6,
            detection_method="form-fuzz-lfi-signature",
            source="module:form-fuzzer",
        )
