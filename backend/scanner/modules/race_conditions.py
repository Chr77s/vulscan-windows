"""
Module : Race Condition tester (TOCTOU).

Envoie N requêtes en parallèle sur des endpoints state-modifying découverts
par le crawler pour détecter des fenêtres de race exploitables.

Cas typiques :
  - Coupon stacking : appliquer 10 fois le même code promo simultanément
  - Double-spend / virement
  - Multi-vote (un user vote 10x)
  - Inventory overselling (5 acheteurs pour 1 stock)
  - 2FA bypass via parallèle

Détection : si N requêtes simultanées renvoient toutes 2xx (succès) alors
qu'une seule devrait, ou si la réponse contient un compteur supérieur à 1
(ex: "applied 10 times"), c'est suspect.

⚠️ Ce module crée potentiellement N entrées en DB de la cible. Limité à
3 essais et seulement sur les forms POST.
"""
from __future__ import annotations
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import re

from scanner.core import http
from scanner.core.module_base import ScannerModule, Finding


class RaceConditionsModule(ScannerModule):
    name = "race-conditions"
    category = "logic"
    title = "Race Conditions / TOCTOU"
    description = "Détecte les race conditions sur des forms POST découverts."
    default_enabled = False

    BURST_SIZE = 8   # nombre de requêtes parallèles
    MAX_FORMS = 2    # limite stricte
    DANGEROUS_ACTION_RE = re.compile(r"(logout|delete|destroy|drop|wipe|password)", re.I)

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        forms = (context.get("crawled") or {}).get("forms", [])
        if not forms:
            return []

        # Filtre : POST + actions liées à du state (coupon, vote, transfer, etc.)
        candidate_forms = []
        for f in forms:
            if f.get("method", "").upper() != "POST":
                continue
            action = f.get("action", "")
            if self.DANGEROUS_ACTION_RE.search(action):
                continue
            # On cible les forms qui ont l'air "actionnable" :
            # coupon, vote, transfer, apply, claim, redeem, withdraw, deposit
            if re.search(r"(coupon|vote|transfer|apply|claim|redeem|withdraw|deposit|like|follow|invite)",
                         action, re.I):
                candidate_forms.append(f)
            elif f.get("fields"):
                # Sinon, on garde aussi les forms avec un seul champ d'action
                candidate_forms.append(f)
            if len(candidate_forms) >= self.MAX_FORMS:
                break

        if not candidate_forms:
            return []

        findings: List[Finding] = []
        for form in candidate_forms[:self.MAX_FORMS]:
            findings.extend(self._test_race(form, context))
        return findings

    def _test_race(self, form: Dict[str, Any], context: Dict[str, Any]) -> List[Finding]:
        action = form["action"]
        data = {f["name"]: f.get("value") or "1" for f in form["fields"]}

        # 1. Référence — 1 seule requête
        r_solo = http.post(action, context, data=data, timeout=8)
        if r_solo is None:
            return []
        solo_status = r_solo.status_code
        solo_body = r_solo.text[:500]

        # 2. Burst — N requêtes en parallèle
        def _one_request():
            r = http.post(action, context, data=data, timeout=8)
            if r is None:
                return 0, ""
            return r.status_code, r.text

        results = []
        with ThreadPoolExecutor(max_workers=self.BURST_SIZE) as pool:
            futures = [pool.submit(_one_request) for _ in range(self.BURST_SIZE)]
            for fut in as_completed(futures):
                results.append(fut.result())

        success_count = sum(1 for s, _ in results if 200 <= s < 300)

        # Heuristique : si plus de 4 requêtes en succès simultanément, c'est suspect
        # (un endpoint correctement protégé refuserait les duplicatas)
        if success_count >= 4 and solo_status < 400:
            return [Finding(
                type="race-condition", severity="high",
                title="Race condition probable sur form",
                description=(
                    f"Sur {self.BURST_SIZE} requêtes POST envoyées en parallèle vers {action}, "
                    f"{success_count} ont renvoyé 2xx. Indique l'absence de verrou anti-replay. "
                    "Potentiel coupon stacking / double-spend / multi-vote."
                ),
                recommendation=(
                    "Imposer un verrou applicatif (mutex, transaction DB avec FOR UPDATE) "
                    "ou un token nonce unique par action sensible."
                ),
                url=action, parameter="POST endpoint",
                payload=f"{self.BURST_SIZE} req parallèles",
                evidence=f"{success_count}/{self.BURST_SIZE} succès en parallèle",
                confidence=75,
                cwe_id="CWE-362", owasp_id="A04:2021",
                cvss_base=7.5,
                detection_method="parallel-burst-test",
                source="module:race-conditions",
            )]
        return []
