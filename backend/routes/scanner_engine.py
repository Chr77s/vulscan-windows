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
    return entry


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
    context = data.get("context", {})
    enabled = data.get("enabled")

    if not target:
        return jsonify({"error": "target requis"}), 400

    engine = get_engine()
    crawl = bool(data.get("crawl", True))
    try:
        findings = engine.run(target, context=context, enabled=enabled, crawl=crawl)
        return jsonify({
            "findings": [f.to_dict() for f in findings],
            "stats": {
                "modules_run": len(enabled) if enabled else
                               len([m for m in engine.list_modules() if m["default_enabled"]]),
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
            "moduleLog": [_module_log_entry(e) for e in engine.last_module_log],
        })
    except Exception as e:
        logger.exception("Scan engine error")
        return jsonify({"error": str(e)}), 500
