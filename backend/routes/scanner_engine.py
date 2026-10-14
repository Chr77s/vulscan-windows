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
                "forms":         (context.get("crawled") or {}).get("forms", [])[:20],
                "endpoints":     (context.get("crawled") or {}).get("api_endpoints", [])[:10],
            },
            "moduleLog": [
                {"module": e["module"], "findings": e["findings"], "elapsedMs": e["elapsed_ms"]}
                for e in engine.last_module_log
            ],
        })
    except Exception as e:
        logger.exception("Scan engine error")
        return jsonify({"error": str(e)}), 500
