"""
OOB (Out-of-Band) Collaborator.

Permet aux modules de détecter des vulnérabilités "blind" — celles dont
la preuve n'apparaît pas dans la réponse HTTP directe.

Principe :
  1. Un module génère un UUID, construit un payload qui force la cible
     à faire une requête vers /oob/log/<uuid>.
  2. Quelques secondes plus tard, le module appelle /oob/check/<uuid>.
  3. Si des hits ont été enregistrés, la vuln est CONFIRMÉE.

Cas d'usage typiques :
  - Blind SSRF : le serveur fait une requête vers notre canary
  - Blind XSS stockée : la victime déclenche le payload depuis un panel admin
  - Blind XXE : entité externe SYSTEM "http://canary/x"
  - Blind RCE : `curl http://canary/x`, `wget http://canary/x`

Note : pour fonctionner avec une cible publique, le canary doit être joignable
depuis Internet (Burp Collaborator est hébergé). En usage local (WebLab,
JuiceCorp), `http://localhost:9876/oob/log/<uuid>` marche directement.
"""
from flask import Blueprint, request, jsonify
import time
import threading
import uuid as uuid_mod

oob_bp = Blueprint("oob", __name__)

# Stockage en mémoire (suffisant pour un scan, pas besoin de persistance)
# Structure : { uuid_str: [{"ts":, "method":, "ip":, "user_agent":, "headers":, "body":}] }
_hits = {}
_lock = threading.Lock()

# TTL d'une signature : purgée si pas hit dans X minutes
TTL_SECONDS = 600


def _purge_old():
    """Supprime les entrées trop anciennes."""
    cutoff = time.time() - TTL_SECONDS
    with _lock:
        for uid in list(_hits.keys()):
            recent = [h for h in _hits[uid] if h["ts"] >= cutoff]
            if recent:
                _hits[uid] = recent
            else:
                del _hits[uid]


@oob_bp.route("/log/<uid>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def log_hit(uid):
    """
    Tout hit reçu sur cette URL est logué. C'est l'endpoint "canary".
    On accepte toutes les méthodes pour maximiser les chances.
    """
    _purge_old()
    hit = {
        "ts": time.time(),
        "method": request.method,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": {k: v for k, v in request.headers.items()},
        "body": request.get_data(as_text=True)[:1000],
        "query": dict(request.args),
    }
    with _lock:
        _hits.setdefault(uid, []).append(hit)

    # Retourner un blank gif 1x1 (taille minimale, content-type inoffensif)
    return ("", 200, {"Content-Type": "text/plain"})


@oob_bp.route("/check/<uid>", methods=["GET"])
def check_hits(uid):
    """Renvoie tous les hits reçus pour ce UUID."""
    _purge_old()
    with _lock:
        hits = list(_hits.get(uid, []))
    return jsonify({
        "uid": uid,
        "hit_count": len(hits),
        "hits": hits,
    })


@oob_bp.route("/new", methods=["POST"])
def new_uuid():
    """Génère un nouveau UUID + son URL canary, pour les modules."""
    uid = uuid_mod.uuid4().hex
    base = request.host_url.rstrip("/")  # http://localhost:9876
    return jsonify({
        "uid": uid,
        "url": f"{base}/oob/log/{uid}",
    })


@oob_bp.route("/stats", methods=["GET"])
def stats():
    """Pour debug : combien de UUIDs actifs ?"""
    _purge_old()
    with _lock:
        return jsonify({
            "active_uids": len(_hits),
            "total_hits": sum(len(v) for v in _hits.values()),
        })
