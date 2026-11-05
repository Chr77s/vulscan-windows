"""Helper OOB (Out-of-Band) — utilisé par les modules pour générer des canaries
et vérifier les hits, via le canal choisi pour le scan.

    from scanner.core.oob import OOBCanary
    canary = OOBCanary.new(context)       # context facultatif -> canal local par défaut
    payload = f"<img src='{canary.url}'>"
    ...
    if canary.wait_for_hit(context):      # borné par la deadline du scan
        # vuln blind confirmée

Le canal provient de `context["oob_channel"]` (posé par l'engine) ; sans lui,
on retombe sur le canal local (endpoint /oob du backend). Un canal `off`
renvoie `url=None` : les modules ne tirent alors aucun payload OOB.
"""
from __future__ import annotations
from typing import Any, Dict, List, Optional
import time
import uuid as uuid_mod


def _channel_from(context: Optional[Dict[str, Any]]):
    ch = (context or {}).get("oob_channel")
    if ch is not None:
        return ch
    from scanner.core.oob_channel import LocalChannel
    return LocalChannel()


class OOBCanary:
    def __init__(self, uid: str, url: Optional[str], channel):
        self.uid = uid
        self.url = url
        self.channel = channel

    @classmethod
    def new(cls, context: Optional[Dict[str, Any]] = None) -> "OOBCanary":
        channel = _channel_from(context)
        uid = uuid_mod.uuid4().hex
        try:
            url = channel.register(uid)
        except Exception:
            url = None
        return cls(uid, url, channel)

    def hits(self) -> List[dict]:
        try:
            return self.channel.poll(self.uid)
        except Exception:
            return []

    def hit_count(self) -> int:
        return len(self.hits())

    def was_hit(self) -> bool:
        return self.hit_count() > 0

    def wait_for_hit(self, context: Optional[Dict[str, Any]] = None,
                     timeout: float = 5, poll: float = 0.5) -> bool:
        """Attend un hit, borné par le plus court de `timeout` et de la deadline du scan."""
        from scanner.core.http import time_left
        hard_deadline = time.monotonic() + timeout
        while True:
            if self.was_hit():
                return True
            if time.monotonic() >= hard_deadline:
                return False
            budget = time_left(context) if context else None
            if budget is not None and budget <= 0:
                return False
            nap = poll if budget is None else min(poll, budget)
            time.sleep(min(nap, 0.5))
