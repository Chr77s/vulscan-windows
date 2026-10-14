"""
Utilitaires WAF — détection et mutation de payloads pour bypass simple.

Approche pragmatique :
  - Détecte la présence d'un WAF (Cloudflare, Akamai, AWS WAF, Imperva, F5, Sucuri...)
  - Si WAF détecté, propose des mutations de payloads couramment utilisées
    pour bypass : case variation, URL encoding double, comment injection, etc.

⚠️ Ces techniques sont des indices basiques — les WAFs modernes (Cloudflare Pro, AWS WAFv2)
les bloquent. Mais 80% des installations de base sont contournables comme ça.
"""
from __future__ import annotations
from typing import Dict, Optional, List, Tuple
import re
import urllib.parse


# (header_pattern, server_pattern, body_pattern, label)
WAF_SIGNATURES: List[Tuple[Optional[str], Optional[str], Optional[str], str]] = [
    (r"^cf-(ray|cache-status)$",        r"cloudflare",                     r"Attention Required.*Cloudflare", "Cloudflare"),
    (r"^x-akamai",                       r"AkamaiGHost",                   r"Reference.*Akamai",              "Akamai"),
    (r"^x-amzn-",                        None,                             r"AWS WAF",                        "AWS WAF"),
    (r"^x-iinfo$",                       None,                             r"Incapsula incident ID",          "Imperva Incapsula"),
    (r"^x-sucuri-id$",                   r"Sucuri/Cloudproxy",             r"Sucuri Website Firewall",        "Sucuri"),
    (r"^x-cdn$",                         r"BIG-?IP",                        r"The requested URL was rejected", "F5 BIG-IP ASM"),
    (None,                               r"barracuda",                      None,                              "Barracuda"),
    (None,                               r"FortiWeb",                       None,                              "FortiWeb"),
    (None,                               r"openresty",                      r"ModSecurity",                    "ModSecurity"),
    (None,                               None,                              r"This request has been blocked", "Generic WAF"),
]


def detect_waf(headers: Dict[str, str], body: str) -> Optional[str]:
    """Renvoie le nom du WAF détecté ou None."""
    lower_headers = {k.lower(): v for k, v in headers.items()}
    server = lower_headers.get("server", "")

    for header_pat, server_pat, body_pat, label in WAF_SIGNATURES:
        if header_pat and any(re.match(header_pat, k, re.I) for k in lower_headers.keys()):
            return label
        if server_pat and re.search(server_pat, server, re.I):
            return label
        if body_pat and re.search(body_pat, body, re.I):
            return label
    return None


# =================================================================
# Mutations de payloads
# =================================================================

def mutate(payload: str) -> List[str]:
    """Génère plusieurs mutations d'un payload pour tenter un bypass WAF.
    Renvoie une liste dédupliquée incluant le payload original.
    """
    out = {payload}

    # 1. Case variation
    out.add(_case_mix(payload))

    # 2. URL encoding (simple)
    out.add(urllib.parse.quote(payload, safe=""))
    # 3. Double URL encoding
    out.add(urllib.parse.quote(urllib.parse.quote(payload, safe=""), safe=""))

    # 4. HTML entity encoding pour XSS
    if "<" in payload or ">" in payload:
        out.add(_html_entity_encode(payload))

    # 5. Comment injection pour SQL
    if "OR" in payload.upper() or "SELECT" in payload.upper() or "UNION" in payload.upper():
        out.add(_sql_comment_inject(payload))

    # 6. Tab / newline injection
    out.add(payload.replace(" ", "\t"))
    out.add(payload.replace(" ", "/**/"))

    # 7. Null byte (legacy, parfois utile)
    out.add(payload + "%00")

    return list(out)


def _case_mix(s: str) -> str:
    """Alterne majuscules et minuscules."""
    res = []
    upper = False
    for c in s:
        if c.isalpha():
            res.append(c.upper() if upper else c.lower())
            upper = not upper
        else:
            res.append(c)
    return "".join(res)


def _html_entity_encode(s: str) -> str:
    return (s.replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace("'", "&#39;")
             .replace('"', "&quot;"))


def _sql_comment_inject(s: str) -> str:
    """Remplace les espaces par /**/ et casse les mots-clés avec /**/."""
    s2 = re.sub(r"\b(OR|AND|UNION|SELECT|FROM)\b",
                lambda m: m.group(1)[0] + "/**/" + m.group(1)[1:],
                s, flags=re.I)
    return s2.replace(" ", "/**/")
