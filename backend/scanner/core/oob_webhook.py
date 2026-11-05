"""Canal OOB via webhook.site (repli quand aucun tunnel n'est disponible).

On crée un token webhook.site, on injecte l'uid dans le CHEMIN de l'URL canary
(`https://webhook.site/<token>/<uid>`), et on interroge l'API des requêtes reçues
pour corréler par uid. Seul l'uid opaque transite par le tiers — jamais de secret.
"""
from __future__ import annotations
from typing import Any, Callable, List, Optional
import time

import requests

API = "https://webhook.site"


def _fetch_requests(token: str) -> List[dict]:
    r = requests.get(f"{API}/token/{token}/requests?sorting=newest", timeout=5)
    r.raise_for_status()
    return r.json().get("data", [])


class WebhookChannel:
    kind = "webhook"

    def __init__(self, token: str, fetch_requests: Callable[[str], List[dict]] = _fetch_requests):
        self.token = token
        self._fetch = fetch_requests

    @classmethod
    def create(cls, post=None) -> Optional["WebhookChannel"]:
        """Crée un token webhook.site. None si l'API est injoignable."""
        post = post or (lambda: requests.post(f"{API}/token", timeout=5))
        try:
            r = post()
            r.raise_for_status()
            token = r.json().get("uuid")
            return cls(token) if token else None
        except Exception:
            return None

    def register(self, uid: str) -> str:
        return f"{API}/{self.token}/{uid}"

    def poll(self, uid: str) -> List[dict]:
        try:
            raw = self._fetch(self.token)
        except Exception:
            return []
        hits = []
        for rq in raw:
            if uid not in (rq.get("url") or ""):
                continue
            headers = rq.get("headers") or {}
            ua = headers.get("user-agent")
            if isinstance(ua, list):
                ua = ua[0] if ua else ""
            hits.append({
                "ts": time.time(),
                "method": rq.get("method", "?"),
                "ip": rq.get("ip", ""),
                "user_agent": ua or "",
                "headers": headers,
                "body": (rq.get("content") or "")[:1000],
                "query": rq.get("query") or {},
            })
        return hits
