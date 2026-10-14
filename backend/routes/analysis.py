from flask import Blueprint, request, jsonify
from bs4 import BeautifulSoup
import difflib, re, logging

logger = logging.getLogger("vulnscan.analysis")
analysis_bp = Blueprint("analysis", __name__)

@analysis_bp.route("/parse-html", methods=["POST"])
def parse_html():
    data = request.get_json(silent=True)
    if not data or "html" not in data:
        return jsonify({"error": "Le champ 'html' est requis"}), 400
    try:
        soup = BeautifulSoup(data["html"], "html.parser")
    except Exception as e:
        return jsonify({"error": "HTML invalide"}), 400

    forms = []
    for form in soup.find_all("form"):
        fields = [{"tag": i.name, "name": i.get("name",""), "type": i.get("type","text")} for i in form.find_all(["input","textarea","select"])]
        forms.append({"action": form.get("action",""), "method": form.get("method","GET").upper(), "fields": fields})

    inline_scripts = [s.get_text()[:500] for s in soup.find_all("script") if not s.get("src") and s.get_text(strip=True)]

    from bs4 import Comment
    comments = [str(c).strip() for c in soup.find_all(string=lambda t: isinstance(t, Comment)) if len(str(c).strip()) > 3]

    return jsonify({"forms": forms, "inline_scripts": inline_scripts[:5], "comments": comments[:10]})

@analysis_bp.route("/headers", methods=["POST"])
def analyze_headers():
    data = request.get_json(silent=True)
    if not data or "headers" not in data:
        return jsonify({"error": "Le champ 'headers' est requis"}), 400
    headers = {k.lower(): v for k, v in data["headers"].items()}
    url = data.get("url", "")
    is_https = url.startswith("https://")
    findings = []
    checks = [
        ("content-security-policy",  "high",   "CSP manquant. Aucune restriction sur les sources de contenu.", "Ajouter : Content-Security-Policy: default-src 'self'"),
        ("x-frame-options",          "medium",  "X-Frame-Options manquant. Risque de clickjacking.", "Ajouter : X-Frame-Options: DENY"),
        ("x-content-type-options",   "low",     "X-Content-Type-Options manquant.", "Ajouter : X-Content-Type-Options: nosniff"),
        ("referrer-policy",          "low",     "Referrer-Policy manquant.", "Ajouter : Referrer-Policy: strict-origin-when-cross-origin"),
    ]
    if is_https:
        checks.append(("strict-transport-security", "high", "HSTS manquant sur HTTPS.", "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    for header, severity, desc, rec in checks:
        if header not in headers:
            findings.append({"type": "missing-header", "severity": severity, "parameter": header, "description": desc, "recommendation": rec})
    return jsonify({"findings": findings})

@analysis_bp.route("/blind-sqli", methods=["POST"])
def analyze_blind_sqli():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Body JSON requis"}), 400
    r_true     = data.get("response_true", "")
    r_false    = data.get("response_false", "")
    r_baseline = data.get("response_baseline", "")
    ratio_true  = difflib.SequenceMatcher(None, r_baseline, r_true).ratio()
    ratio_false = difflib.SequenceMatcher(None, r_baseline, r_false).ratio()
    diff = abs(ratio_true - ratio_false)
    return jsonify({"is_vulnerable": diff > 0.20, "difference": round(diff, 3), "confidence": "high" if diff > 0.4 else "medium" if diff > 0.2 else "low"})
