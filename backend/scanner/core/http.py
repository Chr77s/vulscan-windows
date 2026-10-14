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
import time

logger = logging.getLogger("vulnscan.http")

DEFAULT_TIMEOUT = 8
DEFAULT_UA = "VulnScan/1.4 (security-audit)"
MAX_BODY_SNIPPET = 4096
SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}


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


def _redact_headers(headers):
    """Masque les en-têtes sensibles (Authorization, Cookie, Set-Cookie) avant de les exposer en evidence."""
    return {k: ("***" if k.lower() in SENSITIVE_HEADERS else v) for k, v in (headers or {}).items()}


def _build_evidence(method, url, opts, response, elapsed_ms):
    """Construit les dicts d'evidence request/response à partir des opts fusionnés et de la réponse.

    N'accède jamais à opts["auth"] (le tuple Basic Auth) : seuls headers/data/json sont lus ici,
    donc un éventuel secret Basic Auth ne peut pas fuiter dans l'evidence.
    """
    req_ev = {
        "method": method.upper(),
        "url": url,
        "headers": _redact_headers(opts.get("headers")),
        "body": opts.get("data") if opts.get("data") is not None else opts.get("json"),
    }
    resp_ev = {
        "status": response.status_code,
        "headers": _redact_headers(dict(response.headers)),
        "body_snippet": (response.text or "")[:MAX_BODY_SNIPPET],
        "elapsed_ms": round(elapsed_ms, 1),
    }
    return req_ev, resp_ev


def send(method: str,
         url: str,
         context: Optional[Dict[str, Any]] = None,
         capture: bool = False,
         **kwargs):
    """Envoie une requête HTTP avec l'auth du contexte injectée.

    Par défaut (capture=False) : comportement inchangé, retourne la Response ou None en cas d'erreur.
    Si capture=True : retourne un triplet (response_ou_none, evidence_request_ou_none, evidence_response_ou_none).
    L'evidence ne contient jamais de secret en clair (headers sensibles redactés, tuple Basic Auth jamais lu).
    """
    opts = _merged_kwargs(context, kwargs)
    try:
        start = time.monotonic()
        response = requests.request(method.upper(), url, **opts)
        elapsed_ms = (time.monotonic() - start) * 1000
    except requests.exceptions.RequestException as e:
        logger.debug(f"HTTP {method} {url} failed: {e}")
        return (None, None, None) if capture else None

    if capture:
        return response, *_build_evidence(method, url, opts, response, elapsed_ms)
    return response


def get(url: str, context=None, capture: bool = False, **kwargs):
    return send("GET", url, context, capture=capture, **kwargs)


def post(url: str, context=None, capture: bool = False, **kwargs):
    return send("POST", url, context, capture=capture, **kwargs)


def has_auth(context: Optional[Dict[str, Any]]) -> bool:
    """True si le contexte fournit une auth (utile pour skip certains tests si non-auth)."""
    a = (context or {}).get("auth") or {}
    return bool(a.get("cookies") or a.get("headers") or a.get("basic"))
