"""
Helper HTTP centralisé pour tous les modules.

Pourquoi : chaque module faisait `requests.get(...)` directement. Cela empêchait :
  - L'authentification (cookies/JWT/Bearer) partagée
  - Un User-Agent / timeout cohérent
  - Le rate-limiting global
  - Le logging centralisé

Désormais les modules appellent `send(method, url, context, **kwargs)` et l'auth
définie au niveau du scan est automatiquement injectée.

Le `context` est le dictionnaire passé par l'engine. Il peut contenir :
  context["auth"] = {
      "cookies":      {"sessionid": "abc..."},
      "headers":      {"Authorization": "Bearer eyJ..."},
      "basic":        ("username", "password"),  # optionnel
  }
"""
from __future__ import annotations
from typing import Dict, Any, Optional
import requests
import logging

logger = logging.getLogger("vulnscan.http")

DEFAULT_TIMEOUT = 8
DEFAULT_UA = "VulnScan/1.4 (security-audit)"


def _merged_kwargs(context: Optional[Dict[str, Any]], kwargs: dict) -> dict:
    """Fusionne les paramètres reçus avec l'auth du contexte."""
    out = dict(kwargs)

    # User-Agent par défaut
    headers = dict(out.get("headers") or {})
    headers.setdefault("User-Agent", DEFAULT_UA)

    # Timeout par défaut
    out.setdefault("timeout", DEFAULT_TIMEOUT)

    auth = (context or {}).get("auth") or {}

    # Injection cookies
    auth_cookies = auth.get("cookies") or {}
    if auth_cookies:
        existing = dict(out.get("cookies") or {})
        existing.update(auth_cookies)
        out["cookies"] = existing

    # Injection headers (Authorization, custom...)
    auth_headers = auth.get("headers") or {}
    for k, v in auth_headers.items():
        if k not in headers:
            headers[k] = v

    # Basic Auth si fourni
    if auth.get("basic") and "auth" not in out:
        basic = auth["basic"]
        if isinstance(basic, (list, tuple)) and len(basic) == 2:
            out["auth"] = (basic[0], basic[1])

    out["headers"] = headers
    return out


def send(method: str,
         url: str,
         context: Optional[Dict[str, Any]] = None,
         **kwargs) -> Optional[requests.Response]:
    """Envoie une requête HTTP avec l'auth du contexte injectée. Retourne None en cas d'erreur."""
    try:
        opts = _merged_kwargs(context, kwargs)
        return requests.request(method.upper(), url, **opts)
    except requests.exceptions.RequestException as e:
        logger.debug(f"HTTP {method} {url} failed: {e}")
        return None


def get(url: str, context=None, **kwargs):
    return send("GET", url, context, **kwargs)


def post(url: str, context=None, **kwargs):
    return send("POST", url, context, **kwargs)


def has_auth(context: Optional[Dict[str, Any]]) -> bool:
    """True si le contexte fournit une auth (utile pour skip certains tests si non-auth)."""
    a = (context or {}).get("auth") or {}
    return bool(a.get("cookies") or a.get("headers") or a.get("basic"))
