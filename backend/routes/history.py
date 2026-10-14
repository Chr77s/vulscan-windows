"""
Endpoints d'historique des scans (SQLite côté backend).

  POST /history/save        — sauvegarde un scan complet
  GET  /history/list        — liste paginée
  GET  /history/<id>        — récupère un scan
  POST /history/diff        — compare 2 scans { a, b }
  DELETE /history/<id>      — supprime
"""
from flask import Blueprint, request, jsonify
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.db import init_db, save_scan, list_scans, get_scan, delete_scan, diff_scans

history_bp = Blueprint("history", __name__)

# Init au chargement du blueprint
init_db()


@history_bp.route("/save", methods=["POST"])
def save():
    scan = request.get_json(silent=True) or {}
    if "id" not in scan:
        return jsonify({"error": "id manquant"}), 400
    save_scan(scan)
    return jsonify({"success": True, "id": scan["id"]})


@history_bp.route("/list", methods=["GET"])
def listing():
    limit = int(request.args.get("limit", 50))
    url_q = request.args.get("url")
    return jsonify({"scans": list_scans(limit=limit, url_filter=url_q)})


@history_bp.route("/<scan_id>", methods=["GET"])
def get_one(scan_id):
    scan = get_scan(scan_id)
    if not scan:
        return jsonify({"error": "introuvable"}), 404
    return jsonify(scan)


@history_bp.route("/<scan_id>", methods=["DELETE"])
def delete(scan_id):
    ok = delete_scan(scan_id)
    return jsonify({"success": ok})


@history_bp.route("/diff", methods=["POST"])
def diff():
    body = request.get_json(silent=True) or {}
    a = body.get("a")
    b = body.get("b")
    if not a or not b:
        return jsonify({"error": "a et b requis"}), 400
    return jsonify(diff_scans(a, b))
