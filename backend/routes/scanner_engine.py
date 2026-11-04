"""
Endpoint Flask qui pilote le moteur modulaire scanner/.
Permet à l'extension d'invoquer n'importe quel module enregistré.
"""
from flask import Blueprint, request, jsonify
import logging
import sys
import os

# Charger le moteur (scanner/ est un sibling du dossier routes/)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner.core.jobs import JobStore, TooManyJobs

logger = logging.getLogger("vulnscan.scanner-engine")
scanner_bp = Blueprint("scanner", __name__)

# Initialisation lazy
_engine = None

def get_engine():
    global _engine
    if _engine is None:
        from scanner.core.engine import ScannerEngine
        _engine = ScannerEngine()
        _engine.register_all()  # auto-découverte des modules
        logger.info(f"Moteur initialisé avec {len(_engine.list_modules())} modules")
    return _engine


@scanner_bp.route("/modules", methods=["GET"])
def list_modules():
    """Renvoie la liste des modules disponibles avec métadonnées."""
    return jsonify({"modules": get_engine().list_modules()})


def _strip_field_values(fields):
    """Retire la clé 'value' de chaque champ de formulaire avant de la renvoyer
    à l'extension (Fix 6, final-fix-wave) : la Surface tab ne lit jamais
    field.value (name/type seulement), mais le backend le capturait, le
    transmettait et le stockait quand même — risque de fuite de données
    saisies par l'utilisateur (tokens CSRF, __VIEWSTATE, etc.) sans aucun usage."""
    return [{k: v for k, v in f.items() if k != "value"} for f in (fields or [])]


def _module_log_entry(e):
    """Convertit une entrée brute de engine.last_module_log au format camelCase
    de l'API ; expose status/error quand le module a crashé (Fix 5, final-fix-wave)
    sans changer la forme des entrées réussies."""
    entry = {"module": e["module"], "findings": e["findings"], "elapsedMs": e["elapsed_ms"]}
    if e.get("status") == "error":
        entry["status"] = "error"
        entry["error"] = e.get("error")
    elif e.get("status") == "skipped":
        entry["status"] = "skipped"
        entry["reason"] = e.get("reason")
    return entry


_jobs = JobStore()

# Clés pilotées par le serveur : jamais acceptées du client.
_SERVER_CONTEXT_KEYS = ("deadline", "cancelled", "current_module", "module_log")


def _clean_context(raw):
    """Contexte client assaini : dict uniquement, sans les clés de pilotage serveur.
    (La deadline se mesure sur l'horloge monotone du serveur : celle d'un client n'a
    aucun sens, et une chaîne ferait planter le moteur hors du try → HTTP 500.)"""
    if not isinstance(raw, dict):
        return {}
    return {k: v for k, v in raw.items() if k not in _SERVER_CONTEXT_KEYS}


def _build_run_response(findings, context):
    return {
        "findings": [f.to_dict() for f in findings],
        "stats": {
            "modules_run": len([e for e in context.get("module_log", [])
                                if e.get("status") != "skipped"]),
            "findings_count": len(findings),
            "crawler": context.get("crawled", {}).get("stats", {}),
        },
        "discovery": {
            "urls":          (context.get("crawled") or {}).get("urls", [])[:20],
            "forms":         [
                {**form, "fields": _strip_field_values(form.get("fields"))}
                for form in (context.get("crawled") or {}).get("forms", [])[:20]
            ],
            "endpoints":     (context.get("crawled") or {}).get("api_endpoints", [])[:10],
        },
        "moduleLog": [_module_log_entry(e) for e in context.get("module_log", [])],
    }


@scanner_bp.route("/run", methods=["POST"])
def run_scan():
    """
    Body :
      {
        "target": "https://example.com",
        "context": {...},                   // optionnel
        "enabled": ["headers","info-disclosure"]   // optionnel — sinon default_enabled
      }

    Renvoie : { "findings": [...], "stats": {...} }
    """
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    context = _clean_context(data.get("context"))
    enabled = data.get("enabled")

    if not target:
        return jsonify({"error": "target requis"}), 400

    engine = get_engine()
    crawl = bool(data.get("crawl", True))
    try:
        findings = engine.run(target, context=context, enabled=enabled, crawl=crawl)
        return jsonify(_build_run_response(findings, context))
    except Exception as e:
        logger.exception("Scan engine error")
        return jsonify({"error": str(e)}), 500


@scanner_bp.route("/jobs", methods=["POST"])
def create_job():
    """Lance un scan en arrière-plan ; même corps que /run. 202 {jobId} | 400 | 429."""
    data = request.get_json(silent=True) or {}
    target = data.get("target", "")
    if not target:
        return jsonify({"error": "target requis"}), 400
    engine = get_engine()

    def run_fn(target, ctx, enabled, crawl):
        return engine.run(target, context=ctx, enabled=enabled, crawl=crawl)

    try:
        job_id = _jobs.create(run_fn, target, _clean_context(data.get("context")),
                              data.get("enabled"), bool(data.get("crawl", True)))
    except TooManyJobs:
        return jsonify({"error": "trop de scans en cours"}), 429
    return jsonify({"jobId": job_id}), 202


@scanner_bp.route("/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    snap = _jobs.snapshot(job_id)
    if snap is None:
        return jsonify({"error": "job inconnu"}), 404
    body = {
        "jobId": job_id,
        "status": snap["status"],
        "currentModule": snap["current_module"],
        "moduleLog": [_module_log_entry(e) for e in snap["module_log"]],
        "elapsedMs": snap["elapsed_ms"],
    }
    if snap["status"] in ("done", "cancelled"):
        body["result"] = _build_run_response(snap["findings"], snap["context"])
    if snap["error"] is not None:
        body["error"] = snap["error"]
    return jsonify(body)


@scanner_bp.route("/jobs/<job_id>", methods=["DELETE"])
def cancel_job(job_id):
    if not _jobs.cancel(job_id):
        return jsonify({"error": "job inconnu"}), 404
    return jsonify({"jobId": job_id, "status": "cancelling"}), 202
