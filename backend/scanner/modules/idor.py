"""
Module : IDOR (Insecure Direct Object Reference) — détection HEURISTIQUE.

L'IDOR est difficile à détecter sans contexte d'utilisateur. Notre approche :
  1. Repérer les paramètres numériques incrémentaux (?id=, ?user=, ?order=)
  2. Tester id-1, id+1, id=1 et comparer les réponses :
     - Si réponse différente avec HTTP 200 (pas de redirection vers login) →
       le serveur ne contrôle PAS l'autorisation par utilisateur.
     - Confiance modérée car peut être un objet public légitime.

OWASP A01 / CWE-639.
"""
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import requests
import difflib
import re

from scanner.core.module_base import ScannerModule, Finding


class IdorModule(ScannerModule):
    name = "idor"
    category = "access-control"
    title = "Insecure Direct Object Reference"
    description = "Heuristique : teste les id numériques voisins pour détecter une fuite d'objets non-autorisés."
    default_enabled = False

    ID_PARAMS = {"id", "user_id", "uid", "order_id", "oid", "doc_id", "msg_id",
                 "invoice_id", "post_id", "item_id", "account_id", "session_id"}

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        findings: List[Finding] = []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))

        try:
            r_base = requests.get(target, timeout=8, headers={"User-Agent": "VulnScan/1.2"})
            body_base = r_base.text
        except Exception:
            return findings

        for param_name, base_value in params.items():
            if param_name.lower() not in self.ID_PARAMS:
                continue
            if not re.match(r"^\d+$", base_value):
                continue  # uniquement IDs numériques

            base_id = int(base_value)
            test_ids = [str(base_id + 1), str(base_id - 1), "1", "9999"]

            for new_id in test_ids:
                if new_id == base_value:
                    continue
                try:
                    new_params = dict(params)
                    new_params[param_name] = new_id
                    test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                    r = requests.get(test_url, timeout=8, allow_redirects=False,
                                     headers={"User-Agent": "VulnScan/1.2"})

                    # Bonne signature : 200 + contenu non identique + pas de redirection login
                    is_login_redirect = (
                        r.status_code in (301, 302) and
                        re.search(r"login|signin|auth", r.headers.get("Location", ""), re.I)
                    )
                    if is_login_redirect:
                        break  # Bonne pratique : redirige vers login → pas IDOR

                    if r.status_code == 200:
                        ratio = difflib.SequenceMatcher(None, body_base, r.text).ratio()
                        if 0.2 < ratio < 0.95:  # ni identique ni totalement différent
                            findings.append(Finding(
                                type="idor", severity="high",
                                title=f"IDOR probable sur '{param_name}'",
                                description=(
                                    f"Modifier {param_name}={base_value} en {param_name}={new_id} "
                                    f"renvoie un contenu différent (sim={ratio:.2f}) "
                                    "sans vérification d'autorisation visible."
                                ),
                                recommendation=(
                                    "Côté serveur, valider que l'objet demandé appartient bien à l'utilisateur "
                                    "courant (ex: WHERE id = ? AND owner_id = current_user)."
                                ),
                                url=target, parameter=param_name,
                                payload=f"{param_name}={new_id}",
                                evidence=f"sim(base, alt)={ratio:.2f}, HTTP={r.status_code}",
                                confidence=65,  # modéré — peut être objet public
                                cwe_id="CWE-639", owasp_id="A01:2021",
                                cvss_base=8.1,
                                detection_method="id-walk",
                                source="module:idor",
                            ))
                            break
                except Exception:
                    continue
        return findings
