from flask import Blueprint, jsonify
health_bp = Blueprint("health", __name__)

@health_bp.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "ok",
        "version": "1.2.0",
        "service": "VulnScan Python Backend",
        "endpoints": [
            "/health",
            "/analysis/parse-html",
            "/analysis/headers",
            "/analysis/blind-sqli",
            "/analysis/fetch-headers",
            "/analysis/cve-check",
            "/analysis/correlate",
            "/scanner/modules",
            "/scanner/run",
            "/history/list",
            "/history/save",
            "/history/diff",
        ],
    })
