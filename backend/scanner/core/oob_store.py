"""Magasin de hits OOB partagé.

Les routes Flask (`routes/oob.py`) et le listener canary isolé
(`scanner/core/oob_listener.py`) écrivent tous deux ici, pour que la
corrélation hit↔uid soit la même quel que soit le point d'entrée.
En mémoire + TTL : aucune persistance entre scans (voir la spec, hors périmètre).
"""
from __future__ import annotations
from typing import Any, Dict, List
import threading
import time

TTL_SECONDS = 600

_hits: Dict[str, List[Dict[str, Any]]] = {}
_lock = threading.Lock()


def record_hit(uid: str, hit: Dict[str, Any]) -> None:
    with _lock:
        _hits.setdefault(uid, []).append(hit)


def get_hits(uid: str) -> List[Dict[str, Any]]:
    with _lock:
        return list(_hits.get(uid, []))


def purge_old(ttl_s: int = TTL_SECONDS) -> None:
    cutoff = time.time() - ttl_s
    with _lock:
        for uid in list(_hits.keys()):
            recent = [h for h in _hits[uid] if h.get("ts", 0) >= cutoff]
            if recent:
                _hits[uid] = recent
            else:
                del _hits[uid]


def stats() -> Dict[str, int]:
    with _lock:
        return {"active_uids": len(_hits), "total_hits": sum(len(v) for v in _hits.values())}


def _reset() -> None:
    """Pour les tests : vide le magasin."""
    with _lock:
        _hits.clear()
