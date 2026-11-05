"""
OOB (Out-of-Band) Collaborator — endpoints Flask.

Permet aux modules de détecter des vulnérabilités "blind" — celles dont
la preuve n'apparaît pas dans la réponse HTTP directe.

Principe :
  1. Un module génère un UUID, construit un payload qui force la cible
     à faire une requête vers /oob/log/<uuid>.
  2. Quelques secondes plus tard, le module appelle /oob/check/<uuid>.
  3. Si des hits ont été enregistrés, la vuln est CONFIRMÉE.

Le stockage des hits est délégué à scanner.core.oob_store, partagé avec le
listener canary isolé (scanner.core.oob_listener) pour que la corrélation
hit↔uid soit la même quel que soit le point d'entrée.
"""
from flask import Blueprint, request, jsonify
import time
import uuid as uuid_mod

from scanner.core import oob_store

oob_bp = Blueprint("oob", __name__)


@oob_bp.route("/log/<uid>", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
def log_hit(uid):
    """Tout hit reçu sur cette URL est logué. C'est l'endpoint "canary"."""
    oob_store.purge_old()
    hit = {
        "ts": time.time(),
        "method": request.method,
        "ip": request.headers.get("X-Forwarded-For", request.remote_addr or ""),
        "user_agent": request.headers.get("User-Agent", ""),
        "headers": {k: v for k, v in request.headers.items()},
        "body": request.get_data(as_text=True)[:1000],
        "query": dict(request.args),
    }
    oob_store.record_hit(uid, hit)
    return ("", 200, {"Content-Type": "text/plain"})


@oob_bp.route("/check/<uid>", methods=["GET"])
def check_hits(uid):
    """Renvoie tous les hits reçus pour ce UUID."""
    oob_store.purge_old()
    hits = oob_store.get_hits(uid)
    return jsonify({"uid": uid, "hit_count": len(hits), "hits": hits})


@oob_bp.route("/new", methods=["POST"])
def new_uuid():
    """Génère un nouveau UUID + son URL canary, pour les modules."""
    uid = uuid_mod.uuid4().hex
    base = request.host_url.rstrip("/")
    return jsonify({"uid": uid, "url": f"{base}/oob/log/{uid}"})


@oob_bp.route("/stats", methods=["GET"])
def stats():
    """Pour debug : combien de UUIDs actifs ?"""
    oob_store.purge_old()
    s = oob_store.stats()
    return jsonify({"active_uids": s["active_uids"], "total_hits": s["total_hits"]})
