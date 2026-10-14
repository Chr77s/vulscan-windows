"""
Module : détection SQL Injection (passive — pas de payload envoyé).

Stratégie :
  1. Sur les paramètres d'URL connus (id, user, search, page…), envoie 3 requêtes :
        - baseline normale
        - payload "true" (1=1)
        - payload "false" (1=2)
     puis compare les réponses (Levenshtein ratio) pour détecter Blind SQLi booléen.
  2. Analyse aussi les messages d'erreur SQL classiques dans la réponse baseline
     (you have an error in your SQL syntax, ORA-, ODBC SQL Server, sqlite3.OperationalError…).

⚠️ Cette détection envoie des requêtes — donc à utiliser uniquement sur cibles autorisées.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import difflib
import re
import time

from scanner.core import http
from scanner.core.matchers import HttpResult, Matcher, evaluate
from scanner.core.module_base import ScannerModule, Finding


class SqliModule(ScannerModule):
    name = "sqli"
    category = "injection"
    title = "SQL Injection (Error-based + Blind)"
    description = "Détection passive d'erreurs SQL + test booléen blind sur paramètres GET."
    default_enabled = False  # Désactivé par défaut — module actif

    ERROR_PATTERNS = [
        (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
        (re.compile(r"warning.*mysql_", re.I),                       "MySQL"),
        (re.compile(r"ora-\d{5}", re.I),                             "Oracle"),
        (re.compile(r"microsoft.*odbc.*sql server", re.I),           "MSSQL"),
        (re.compile(r"unclosed quotation mark", re.I),               "MSSQL"),
        (re.compile(r"sqlite3?\.operationalerror", re.I),            "SQLite"),
        (re.compile(r"psycopg2\.errors", re.I),                      "PostgreSQL"),
        (re.compile(r"pg::syntaxerror", re.I),                       "PostgreSQL"),
    ]

    SUSPECT_PARAMS = {"id", "user", "user_id", "uid", "page", "p", "category",
                      "cat", "search", "q", "query", "name", "username",
                      "email", "order", "sort", "type"}

    # Payloads time-based : (payload, dbms, sleep_seconds)
    TIME_PAYLOADS = [
        ("' AND SLEEP(4)-- ",                       "MySQL",      4),
        ("'; SELECT pg_sleep(4)-- ",                "PostgreSQL", 4),
        ("'; WAITFOR DELAY '0:0:4'-- ",             "MSSQL",      4),
        ("' OR 1=(SELECT 1 FROM PG_SLEEP(4))-- ",   "PostgreSQL", 4),
    ]
    # Seuil : on confirme si le delta de temps est ≥ 3.5s (marge pour latence)
    TIME_THRESHOLD = 3.5

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))

        try:
            r_base = http.get(target, context, timeout=8,
                               headers={"User-Agent": "VulnScan/1.2"})
            if r_base is None:
                return findings
            body_base = r_base.text
        except Exception:
            return findings

        # 1. Erreurs SQL dans la baseline (passive)
        for pattern, dbms in self.ERROR_PATTERNS:
            if pattern.search(body_base):
                findings.append(Finding(
                    type="sqli", severity="high",
                    title="SQL Error Disclosure",
                    description=f"Le serveur révèle une erreur {dbms} dans la réponse — indice fort d'une SQLi exploitable.",
                    recommendation="Désactiver l'affichage d'erreurs SQL en production. Utiliser des requêtes paramétrées.",
                    url=target, parameter="(réponse complète)",
                    evidence=pattern.search(body_base).group(0)[:200],
                    confidence=85, cwe_id="CWE-209", owasp_id="A03:2021",
                    cvss_base=8.6,
                    detection_method="error-based-passive",
                    source="module:sqli",
                ))
                break  # une seule détection par DBMS suffit

        # 2. Blind SQLi booléen + time-based sur chaque paramètre suspect
        for param_name, base_value in params.items():
            if param_name.lower() not in self.SUSPECT_PARAMS:
                continue

            # 2A. Boolean-based blind
            try:
                true_payload  = f"{base_value} AND 1=1-- "
                false_payload = f"{base_value} AND 1=2-- "
                r_true  = self._fetch_with_param(parsed, params, param_name, true_payload, context)
                r_false = self._fetch_with_param(parsed, params, param_name, false_payload, context)
                if r_true is not None and r_false is not None:
                    ratio_true  = difflib.SequenceMatcher(None, body_base, r_true).ratio()
                    ratio_false = difflib.SequenceMatcher(None, body_base, r_false).ratio()
                    delta = abs(ratio_true - ratio_false)
                    if delta > 0.25:
                        findings.append(Finding(
                            type="sqli", severity="critical",
                            title="Blind SQL Injection (boolean)",
                            description=(
                                f"Paramètre '{param_name}' réagit différemment à 1=1 vs 1=2 "
                                f"(Δ={delta:.2f}). Signe fort d'une Blind SQLi booléenne."
                            ),
                            recommendation="Utiliser des requêtes paramétrées (prepared statements).",
                            url=target, parameter=param_name, payload=true_payload,
                            evidence=f"sim(base, true)={ratio_true:.2f}, sim(base, false)={ratio_false:.2f}",
                            confidence=int(70 + min(delta, 0.5) * 60),
                            cwe_id="CWE-89", owasp_id="A03:2021",
                            cvss_base=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            detection_method="boolean-based-blind",
                            source="module:sqli",
                        ))
                        continue  # déjà confirmé, passer au param suivant
            except Exception:
                pass

            # 2B. Time-based blind — mesure le delta de réponse
            try:
                # Baseline timing : 2 mesures pour réduire le bruit
                base_1 = self._timed_fetch(parsed, params, param_name, base_value, context)
                base_2 = self._timed_fetch(parsed, params, param_name, base_value, context)
                if base_1 is None or base_2 is None:
                    continue
                base_time_1, _ = base_1
                base_time_2, _ = base_2
                baseline = max(base_time_1, base_time_2)

                for payload, dbms, sleep_s in self.TIME_PAYLOADS:
                    full_payload = f"{base_value}{payload}"
                    timed = self._timed_fetch(parsed, params, param_name, full_payload, context)
                    if timed is None:
                        continue
                    t, measured_at = timed
                    delta = t - baseline
                    result = HttpResult(status=0, headers={}, body="", elapsed_ms=delta * 1000)
                    if evaluate([Matcher(type="time", min_delay_ms=self.TIME_THRESHOLD * 1000)], "and", result):
                        # Confirmation par timing : on réémet une requête de confirmation
                        # finale uniquement, pour capturer l'evidence request/response.
                        confirm_url = self._url_with_param(parsed, params, param_name, full_payload)
                        _, req_ev, resp_ev = http.get(confirm_url, context, capture=True, timeout=12,
                                                       headers={"User-Agent": "VulnScan/1.4"})
                        findings.append(Finding(
                            type="sqli", severity="critical",
                            title=f"Blind SQL Injection (time-based, {dbms})",
                            description=(
                                f"Le paramètre '{param_name}' provoque un délai de {delta:.1f}s "
                                f"sur le payload {dbms} SLEEP({sleep_s}). "
                                "Preuve forte d'une SQLi exploitable même sans retour visible."
                            ),
                            recommendation=(
                                "Utiliser des requêtes paramétrées. Désactiver les fonctions "
                                "de sommeil côté DB en prod si possible."
                            ),
                            url=target, parameter=param_name, payload=full_payload,
                            evidence=f"baseline={baseline:.2f}s, payload={t:.2f}s, Δ={delta:.2f}s",
                            confidence=95,
                            cwe_id="CWE-89", owasp_id="A03:2021",
                            cvss_base=9.8,
                            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            detection_method="time-based-blind",
                            source="module:sqli",
                            evidence_request=req_ev, evidence_response=resp_ev,
                            # Réutilise l'horodatage déjà mesuré par _timed_fetch (celui de la
                            # requête confirmante) plutôt que de relire time.time() ici : ce module
                            # a son propre `import time`, mais c'est le même objet module que celui
                            # de module_base.Finding (default_factory de detected_at) — relire
                            # l'horloge à cet endroit consommerait une valeur imprévue de tout
                            # mock posé sur scanner.modules.sqli.time.time.
                            detected_at=int(measured_at * 1000),
                        ))
                        break  # une preuve par param suffit
            except Exception:
                continue

        return findings

    @staticmethod
    def _url_with_param(parsed, original_params, param_name, value) -> str:
        params = dict(original_params)
        params[param_name] = value
        return urlunparse(parsed._replace(query=urlencode(params)))

    @staticmethod
    def _timed_fetch(parsed, original_params, param_name, value, context):
        # type: (...) -> tuple[float, float] | None
        """Renvoie (delta, measured_at) pour une requête, ou None en cas d'erreur.

        `delta` est le temps écoulé, mesuré via time.time() (indépendamment de http.py,
        qui mesure séparément via time.monotonic() pour le rate-limiting/evidence).
        `measured_at` est l'horodatage (epoch) pris juste après la réponse — réutilisable
        comme `detected_at` sans relire l'horloge une fois la confirmation établie.
        """
        try:
            new_url = SqliModule._url_with_param(parsed, original_params, param_name, value)
            t0 = time.time()
            http.get(new_url, context, timeout=12, headers={"User-Agent": "VulnScan/1.4"})
            t1 = time.time()
            return t1 - t0, t1
        except Exception:
            return None

    @staticmethod
    def _fetch_with_param(parsed, original_params, param_name, new_value, context):
        # type: (...) -> str | None  (renvoie None en cas d'échec)
        try:
            new_url = SqliModule._url_with_param(parsed, original_params, param_name, new_value)
            r = http.get(new_url, context, timeout=8,
                          headers={"User-Agent": "VulnScan/1.2"})
            if r is None:
                return None
            return r.text
        except Exception:
            return None
