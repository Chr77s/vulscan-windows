"""Sélecteur de canal OOB.

Choisit, au démarrage d'un scan, par où le canary sera joignable :
- local   : la cible est locale -> endpoint /oob/log du backend (store partagé).
- tunnel  : cible publique -> tunnel (cloudflared/localtunnel) sur le listener isolé.
- webhook : cible publique, repli -> webhook.site.
- off     : aucun canal -> les modules blind restent inertes (détection directe seule).

Les fabriques `make_tunnel` / `make_webhook` sont injectables pour les tests ;
par défaut elles pointent sur les vraies implémentations (Tasks 3/4).
"""
from __future__ import annotations
from typing import Any, Callable, List, Optional
from urllib.parse import urlparse
import os

from scanner.core import oob_store

OOB_BASE = os.environ.get("VULNSCAN_OOB_BASE", "http://127.0.0.1:9876")

_LOCAL_SUFFIXES = (".test", ".localhost")
_LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]"}


def is_local_target(target: str) -> bool:
    host = (urlparse(target).hostname or "").lower()
    if host in _LOCAL_HOSTS:
        return True
    return any(host == s.lstrip(".") or host.endswith(s) for s in _LOCAL_SUFFIXES)


class LocalChannel:
    kind = "local"

    def __init__(self, base: str = OOB_BASE):
        self.base = base.rstrip("/")

    def register(self, uid: str) -> str:
        return f"{self.base}/oob/log/{uid}"

    def poll(self, uid: str) -> List[dict]:
        return oob_store.get_hits(uid)


class NullChannel:
    kind = "off"

    def register(self, uid: str) -> Optional[str]:
        return None

    def poll(self, uid: str) -> List[dict]:
        return []


def _default_make_tunnel():
    # Le câblage tunnel+listener est fourni par l'engine (Task 7) via le paramètre
    # make_tunnel de select_channel. Sans lui, pas de tunnel -> repli webhook/off.
    return None


def _default_make_webhook():
    from scanner.core.oob_webhook import WebhookChannel
    return WebhookChannel.create()


def select_channel(target: str, mode: str = "auto",
                   make_tunnel: Callable[[], Any] = _default_make_tunnel,
                   make_webhook: Callable[[], Any] = _default_make_webhook) -> Any:
    """Retourne le canal choisi. Jamais d'exception : un échec de canal -> NullChannel."""
    mode = (mode or "auto").lower()
    if mode == "off":
        return NullChannel()
    if mode == "local":
        return LocalChannel()
    if mode == "webhook":
        return make_webhook() or NullChannel()
    if mode == "tunnel":
        return make_tunnel() or NullChannel()
    # auto
    if is_local_target(target):
        return LocalChannel()
    return make_tunnel() or make_webhook() or NullChannel()
