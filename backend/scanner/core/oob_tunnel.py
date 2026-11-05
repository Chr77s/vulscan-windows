"""Gestionnaire de tunnel pour exposer le listener canary isolé.

Lance cloudflared (quick tunnel, HTTPS, sans compte) ou localtunnel, parse
l'URL publique, et fournit un TunnelChannel (register sur l'URL publique,
poll sur le store local). Le tunnel ne pointe QUE sur le port du listener
isolé — jamais sur le backend complet (voir spec, isolation).
"""
from __future__ import annotations
from typing import Any, Callable, List, Optional, Tuple
import os
import re
import shutil
import subprocess
import time

from scanner.core import oob_store

_URL_RE = re.compile(r"https://[a-z0-9.-]+\.(?:trycloudflare\.com|loca\.lt)\S*", re.I)


def detect_bin(which: Callable[[str], Optional[str]] = shutil.which) -> Optional[str]:
    override = os.environ.get("VULNSCAN_TUNNEL_BIN")
    if override:
        return override
    for name in ("cloudflared", "lt", "localtunnel"):
        p = which(name)
        if p:
            return p
    return None


def start_tunnel(port: int,
                 spawn: Callable[[list], Any] = None,
                 detect: Callable[[], Optional[str]] = detect_bin,
                 timeout_s: float = 15,
                 clock: Callable[[], float] = time.monotonic) -> Optional[Tuple[str, Callable[[], None]]]:
    """Démarre un tunnel vers 127.0.0.1:<port>. Renvoie (url_publique, stop) ou None."""
    binp = detect()
    if not binp:
        return None
    if "cloudflared" in binp:
        args = [binp, "tunnel", "--url", f"http://127.0.0.1:{port}"]
    else:
        args = [binp, "--port", str(port)]
    spawn = spawn or (lambda a: subprocess.Popen(
        a, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1))
    proc = spawn(args)
    if proc is None:
        return None

    def stop():
        try:
            proc.terminate()
        except Exception:
            pass

    start = clock()
    while True:
        line = proc.stdout.readline() if proc.stdout else ""
        m = _URL_RE.search(line or "")
        if m:
            return m.group(0), stop
        if clock() - start > timeout_s or (line == "" and proc.poll() is not None):
            stop()
            return None


class TunnelChannel:
    kind = "tunnel"

    def __init__(self, base: str, stop: Optional[Callable[[], None]] = None):
        self.base = base.rstrip("/")
        self._stop = stop

    def register(self, uid: str) -> str:
        return f"{self.base}/oob/log/{uid}"

    def poll(self, uid: str) -> List[dict]:
        return oob_store.get_hits(uid)

    def stop(self) -> None:
        if self._stop:
            self._stop()
