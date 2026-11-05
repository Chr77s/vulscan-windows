"""Listener canary isolé.

Un serveur WSGI minimal, lié à 127.0.0.1, qui ne sert QUE /oob/log/<uid>
(toutes méthodes) et renvoie 404 partout ailleurs. C'est le SEUL point exposé
par le tunnel — jamais le backend complet (voir spec, isolation de sécurité).
Les hits vont dans le store partagé (scanner.core.oob_store).
"""
from __future__ import annotations
from typing import Callable, Tuple
import re
import threading
import time
from urllib.parse import parse_qs

from werkzeug.serving import make_server

from scanner.core import oob_store

_LOG_RE = re.compile(r"^/oob/log/([^/]+)/?$")


def _app(environ, start_response):
    path = environ.get("PATH_INFO", "") or ""
    m = _LOG_RE.match(path)
    if not m:
        start_response("404 Not Found", [("Content-Type", "text/plain")])
        return [b"not found"]
    uid = m.group(1)
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        length = 0
    body = environ["wsgi.input"].read(length)[:1000].decode("utf-8", "replace") if length else ""
    hit = {
        "ts": time.time(),
        "method": environ.get("REQUEST_METHOD", "?"),
        "ip": environ.get("HTTP_X_FORWARDED_FOR") or environ.get("REMOTE_ADDR", ""),
        "user_agent": environ.get("HTTP_USER_AGENT", ""),
        "headers": {k[5:].replace("_", "-").title(): v
                    for k, v in environ.items() if k.startswith("HTTP_")},
        "body": body,
        "query": {k: v[0] if len(v) == 1 else v
                  for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()},
    }
    oob_store.record_hit(uid, hit)
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b""]


def start_listener(port: int = 0, host: str = "127.0.0.1") -> Tuple[int, Callable[[], None]]:
    """Démarre le listener dans un thread. Renvoie (port_effectif, stop_fn)."""
    srv = make_server(host, port, _app, threaded=True)
    actual_port = srv.server_port
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()

    def stop():
        try:
            srv.shutdown()
        except Exception:
            pass

    return actual_port, stop
