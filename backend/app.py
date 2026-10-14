"""
VulnScan Backend Python
Serveur Flask sur localhost:9876
Lancer : python app.py
"""
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
import logging, sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", handlers=[logging.StreamHandler(sys.stdout)])
logger = logging.getLogger("vulnscan")

app = Flask(__name__)
CORS(app, origins=["chrome-extension://*"], supports_credentials=False)

from routes.health         import health_bp
from routes.analysis       import analysis_bp
from routes.augment        import augment_bp
from routes.scanner_engine import scanner_bp
from routes.history        import history_bp
from routes.oob            import oob_bp
app.register_blueprint(health_bp)
app.register_blueprint(analysis_bp,  url_prefix="/analysis")
app.register_blueprint(augment_bp,   url_prefix="/analysis")
app.register_blueprint(scanner_bp,   url_prefix="/scanner")
app.register_blueprint(history_bp,   url_prefix="/history")
app.register_blueprint(oob_bp,       url_prefix="/oob")

@app.before_request
def security_check():
    # Les endpoints OOB doivent être joignables depuis n'importe où
    # (la cible doit pouvoir hit le canary). On les exclut du filtre.
    if request.path.startswith("/oob/log/"):
        return None

    origin  = request.headers.get("Origin", "")
    referer = request.headers.get("Referer", "")
    if not origin and not referer:
        return None
    if origin.startswith("chrome-extension://") or referer.startswith("chrome-extension://"):
        return None
    logger.warning(f"Requete refusee depuis origin={origin}")
    return jsonify({"error": "Acces refuse"}), 403

@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["Cache-Control"]          = "no-store"
    return response

if __name__ == "__main__":
    logger.info("=" * 50)
    logger.info("VulnScan Backend Python demarre")
    logger.info("Ecoute sur http://127.0.0.1:9876")
    logger.info("=" * 50)
    app.run(host="127.0.0.1", port=9876, debug=False, threaded=True)
