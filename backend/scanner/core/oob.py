"""
Helper OOB (Out-of-Band) — utilisé par les modules pour générer des canaries
et vérifier les hits.

Usage typique dans un module :

    from scanner.core.oob import OOBCanary

    canary = OOBCanary.new()
    payload = f"<img src='{canary.url}'>"
    requests.post(target, data={"comment": payload})

    # Plus tard...
    time.sleep(2)
    if canary.was_hit():
        # Vuln blind XSS confirmée
        ...

Implémentation : appelle les endpoints /oob/new et /oob/check côté backend Flask.
Le helper utilise donc HTTP local (localhost:9876) pour communiquer avec son
propre Flask — c'est simple et ça fonctionne pour les scans sur cibles internes.
"""
from __future__ import annotations
from typing import Optional
import requests
import time
import uuid as uuid_mod
import os

# URL du backend (lui-même) — par défaut localhost:9876
OOB_BASE = os.environ.get("VULNSCAN_OOB_BASE", "http://127.0.0.1:9876")


class OOBCanary:
    def __init__(self, uid: str, url: str):
        self.uid = uid
        self.url = url

    @classmethod
    def new(cls) -> "OOBCanary":
        """Crée un nouveau canary. Fallback local si endpoint pas joignable."""
        try:
            r = requests.post(f"{OOB_BASE}/oob/new", timeout=3)
            if r.ok:
                data = r.json()
                return cls(data["uid"], data["url"])
        except Exception:
            pass
        # Fallback : génère localement
        uid = uuid_mod.uuid4().hex
        return cls(uid, f"{OOB_BASE}/oob/log/{uid}")

    def was_hit(self) -> bool:
        """Renvoie True si au moins 1 hit a été reçu pour ce uuid."""
        return self.hit_count() > 0

    def hit_count(self) -> int:
        try:
            r = requests.get(f"{OOB_BASE}/oob/check/{self.uid}", timeout=3)
            if r.ok:
                return r.json().get("hit_count", 0)
        except Exception:
            return 0
        return 0

    def hits(self) -> list:
        """Renvoie la liste détaillée des hits."""
        try:
            r = requests.get(f"{OOB_BASE}/oob/check/{self.uid}", timeout=3)
            if r.ok:
                return r.json().get("hits", [])
        except Exception:
            return []
        return []

    def wait_for_hit(self, timeout: int = 5, poll: float = 0.5) -> bool:
        """Attend jusqu'à `timeout` secondes qu'un hit arrive."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.was_hit():
                return True
            time.sleep(poll)
        return False
