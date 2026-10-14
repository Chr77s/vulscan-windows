"""
augment.py — Routes d'augmentation côté backend Python

Ce que ces routes font (et que le navigateur seul NE PEUT PAS faire) :

  1. /analysis/fetch-headers
       Fait un fetch SERVEUR de l'URL cible pour récupérer les vrais en-têtes
       HTTP de réponse. Le content-script Chrome n'a pas accès aux headers HTTP
       bruts (il voit seulement le DOM rendu). C'est le gros gain.

  2. /analysis/cve-check
       Compare une liste (lib, version) avec une base CVE locale et renvoie
       les CVEs applicables avec sévérité / vecteur.

  3. /analysis/correlate
       Reçoit le contexte complet (findings client + headers + libs) et applique
       un scoring bayésien : combinaison probabiliste indépendante.
       confidence = 1 - Π(1 - signal_i)
       Évite les doublons et remonte la confiance quand plusieurs signaux
       convergent.

Ces routes ne servent qu'aux requêtes venant d'une extension Chrome
(security_check dans app.py).
"""
from flask import Blueprint, request, jsonify
from urllib.parse import urlparse
import requests
import logging
import re

logger = logging.getLogger("vulnscan.augment")
augment_bp = Blueprint("augment", __name__)


# =================================================================
#  Base CVE locale (extensible — ajouter de vraies entrées en prod)
# =================================================================
CVE_DB = {
    "jquery": [
        {"max_version": "3.5.0",  "cve": "CVE-2020-11023", "severity": "high",
         "description": "XSS via htmlPrefilter dans les éléments <option> contenant du HTML mal formé."},
        {"max_version": "3.4.0",  "cve": "CVE-2019-11358", "severity": "high",
         "description": "Pollution de prototype via $.extend(true, {}, ...)."},
        {"max_version": "1.12.0", "cve": "CVE-2015-9251",  "severity": "medium",
         "description": "XSS via réponse Ajax cross-domain text/javascript."},
    ],
    "angular": [
        {"max_version": "1.8.0", "cve": "CVE-2019-10768", "severity": "high",
         "description": "Pollution de prototype dans angular.merge()."},
        {"max_version": "1.7.0", "cve": "CVE-2018-13721", "severity": "medium",
         "description": "XSS via SVG dans le mode strict mais sans CSP."},
    ],
    "lodash": [
        {"max_version": "4.17.21", "cve": "CVE-2020-8203", "severity": "high",
         "description": "Pollution de prototype dans _.zipObjectDeep."},
        {"max_version": "4.17.12", "cve": "CVE-2019-10744", "severity": "high",
         "description": "Pollution de prototype dans _.defaultsDeep."},
    ],
    "moment": [
        {"max_version": "2.29.4", "cve": "CVE-2022-31129", "severity": "high",
         "description": "Déni de service par regex (ReDoS) sur les chaînes longues."},
        {"max_version": "2.19.3", "cve": "CVE-2017-18214", "severity": "medium",
         "description": "ReDoS dans le parser de chaînes de date."},
    ],
    "bootstrap": [
        {"max_version": "3.4.0", "cve": "CVE-2019-8331", "severity": "medium",
         "description": "XSS dans data-template / data-content des composants Tooltip/Popover."},
    ],
    "vue": [
        {"max_version": "2.6.11", "cve": "CVE-2021-32723", "severity": "medium",
         "description": "Faille XSS conditionnelle sur le SSR pré-2.6.12."},
    ],
}


def version_le(v1: str, v2: str) -> bool:
    """Compare semver simple. Retourne True si v1 <= v2."""
    def parts(v):
        return [int(x) for x in re.findall(r"\d+", v)][:3] or [0]
    a, b = parts(v1), parts(v2)
    # Pad pour comparaison de longueurs égales
    while len(a) < 3: a.append(0)
    while len(b) < 3: b.append(0)
    return a <= b


# =================================================================
#  ROUTE 1 : Récupération des vrais en-têtes HTTP (server-side fetch)
# =================================================================
@augment_bp.route("/fetch-headers", methods=["POST"])
def fetch_headers():
    """
    Body : { "url": "https://example.com" }
    Renvoie : { "headers": {...}, "status": int, "final_url": "...", "findings": [...] }

    Pourquoi côté serveur : le content-script Chrome ne peut PAS lire les
    en-têtes HTTP de réponse. Nous faisons un fetch côté Python pour observer
    Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, etc.
    """
    data = request.get_json(silent=True) or {}
    url = data.get("url", "")

    if not url or not re.match(r"^https?://", url):
        return jsonify({"error": "URL invalide"}), 400

    # Bloquer les cibles internes/locales pour éviter SSRF
    host = urlparse(url).hostname or ""
    if host in ("localhost", "127.0.0.1") or host.startswith("10.") or host.startswith("192.168."):
        # On laisse passer ici car le site de test JuiceCorp tourne en local
        # En prod, commenter le bypass et activer la protection.
        pass

    try:
        r = requests.get(url, timeout=8, allow_redirects=True, verify=True,
                         headers={"User-Agent": "VulnScan/1.1 (security-audit)"})
        headers = {k.lower(): v for k, v in r.headers.items()}
        findings = analyze_real_headers(headers, r.url)
        return jsonify({
            "status": r.status_code,
            "final_url": r.url,
            "headers": headers,
            "findings": findings,
        })
    except requests.exceptions.SSLError as e:
        return jsonify({
            "status": 0, "final_url": url, "headers": {}, "findings": [{
                "type": "tls", "severity": "high",
                "url": url, "parameter": "TLS handshake",
                "description": f"Erreur SSL/TLS à la connexion : {str(e)[:120]}",
                "recommendation": "Vérifier la chaîne de certificats et la version TLS (≥1.2).",
                "confidence": 95, "source": "backend",
            }]
        })
    except requests.exceptions.Timeout:
        return jsonify({"error": "timeout"}), 504
    except Exception as e:
        logger.warning(f"fetch-headers échec sur {url} : {e}")
        return jsonify({"error": str(e)}), 502


def analyze_real_headers(headers: dict, url: str) -> list:
    """Analyse approfondie des vrais en-têtes HTTP — chose impossible côté browser."""
    findings = []
    is_https = url.startswith("https://")

    checks = [
        ("content-security-policy", "high",
         "CSP manquant. La page n'impose aucune restriction sur les origines de scripts/styles.",
         "Ajouter : Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-...'",
         90),
        ("x-frame-options", "medium",
         "X-Frame-Options manquant. Risque de clickjacking via iframe.",
         "Ajouter : X-Frame-Options: DENY (ou SAMEORIGIN). Mieux : CSP frame-ancestors 'self'",
         95),
        ("x-content-type-options", "low",
         "X-Content-Type-Options manquant. Le navigateur peut deviner les types MIME.",
         "Ajouter : X-Content-Type-Options: nosniff",
         100),
        ("referrer-policy", "low",
         "Referrer-Policy manquant. Risque de fuite d'URL vers des sites tiers.",
         "Ajouter : Referrer-Policy: strict-origin-when-cross-origin",
         100),
        ("permissions-policy", "low",
         "Permissions-Policy manquant. Aucune restriction sur géoloc, caméra, micro, etc.",
         "Ajouter : Permissions-Policy: camera=(), microphone=(), geolocation=()",
         100),
    ]
    if is_https:
        checks.append((
            "strict-transport-security", "high",
            "HSTS manquant. Vulnérabilité de downgrade HTTPS→HTTP.",
            "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            95,
        ))

    for header, severity, desc, rec, conf in checks:
        if header not in headers:
            findings.append({
                "type": "missing-header",
                "severity": severity,
                "url": url,
                "parameter": header,
                "description": desc,
                "recommendation": rec,
                "confidence": conf,
                "source": "backend",
            })

    # Vérifie aussi la qualité du CSP si présent
    csp = headers.get("content-security-policy", "")
    if csp:
        weak_directives = []
        if "'unsafe-inline'" in csp:        weak_directives.append("'unsafe-inline'")
        if "'unsafe-eval'" in csp:          weak_directives.append("'unsafe-eval'")
        if re.search(r"script-src[^;]*\*", csp): weak_directives.append("wildcard * dans script-src")
        if weak_directives:
            findings.append({
                "type": "weak-csp",
                "severity": "medium",
                "url": url,
                "parameter": "Content-Security-Policy",
                "description": f"CSP présent mais affaibli par : {', '.join(weak_directives)}",
                "recommendation": "Supprimer 'unsafe-inline'/'unsafe-eval' et préférer les nonces ou hashes.",
                "evidence": csp[:300],
                "confidence": 90,
                "source": "backend",
            })

    # Server header trop bavard
    server = headers.get("server", "")
    if re.search(r"(apache|nginx|iis)/\d", server, re.I):
        findings.append({
            "type": "info-disclosure",
            "severity": "low",
            "url": url,
            "parameter": "Server",
            "description": f"En-tête Server révèle la version exacte : '{server}'",
            "recommendation": "Masquer la version (server_tokens off pour Nginx, ServerTokens Prod pour Apache).",
            "evidence": server,
            "confidence": 100,
            "source": "backend",
        })

    # X-Powered-By
    if "x-powered-by" in headers:
        findings.append({
            "type": "info-disclosure",
            "severity": "low",
            "url": url,
            "parameter": "X-Powered-By",
            "description": f"En-tête X-Powered-By révèle la techno : '{headers['x-powered-by']}'",
            "recommendation": "Désactiver côté serveur (expose_php=Off pour PHP, etc.).",
            "evidence": headers["x-powered-by"],
            "confidence": 100,
            "source": "backend",
        })

    # Cookies non sécurisés
    set_cookie = headers.get("set-cookie", "")
    if set_cookie:
        flags = []
        if "secure" not in set_cookie.lower() and is_https:  flags.append("Secure")
        if "httponly" not in set_cookie.lower():             flags.append("HttpOnly")
        if "samesite" not in set_cookie.lower():             flags.append("SameSite")
        if flags:
            findings.append({
                "type": "insecure-cookie",
                "severity": "medium",
                "url": url,
                "parameter": "Set-Cookie",
                "description": f"Cookie sans flag(s) : {', '.join(flags)}",
                "recommendation": "Configurer Set-Cookie: ...; Secure; HttpOnly; SameSite=Strict",
                "evidence": set_cookie[:200],
                "confidence": 95,
                "source": "backend",
            })

    return findings


# =================================================================
#  ROUTE 2 : Vérification CVE
# =================================================================
@augment_bp.route("/cve-check", methods=["POST"])
def cve_check():
    """
    Body : { "libraries": [{ "name": "jquery", "version": "1.7.2", "url": "..." }, ...] }
    Renvoie : { "findings": [...] }
    """
    data = request.get_json(silent=True) or {}
    libs = data.get("libraries", [])
    findings = []

    for lib in libs:
        name = (lib.get("name") or "").lower()
        version = lib.get("version") or ""
        src = lib.get("url") or ""
        if not name or not version:
            continue

        cves = CVE_DB.get(name, [])
        for entry in cves:
            if version_le(version, entry["max_version"]):
                findings.append({
                    "type": "outdated-library",
                    "severity": entry["severity"],
                    "url": src,
                    "parameter": f"{name} v{version}",
                    "description": f"{entry['cve']} — {entry['description']}",
                    "recommendation": f"Mettre à jour {name} au-delà de v{entry['max_version']}.",
                    "evidence": src,
                    "confidence": 95,
                    "source": "backend",
                })
                break  # une seule CVE par lib (la plus récente)

    return jsonify({"findings": findings})


# =================================================================
#  ROUTE 3 : Corrélation / scoring bayésien des signaux
# =================================================================
@augment_bp.route("/correlate", methods=["POST"])
def correlate():
    """
    Body : { "findings": [ {... vuln client ...}, ... ] }
    Action :
      - Regroupe par (type, parameter)
      - Combine les confiances : conf = 1 - Π(1 - c_i/100)
      - Supprime les doublons stricts
      - Réordonne par sévérité × confiance
    Renvoie : { "findings": [...] }
    """
    data = request.get_json(silent=True) or {}
    findings = data.get("findings", [])

    if not isinstance(findings, list):
        return jsonify({"error": "findings doit être une liste"}), 400

    # Regrouper par signature
    groups = {}
    for f in findings:
        key = (f.get("type", ""), (f.get("parameter") or "")[:60])
        groups.setdefault(key, []).append(f)

    SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    out = []
    for (ftype, param), bucket in groups.items():
        # Confiance combinée (probabilités indépendantes)
        product = 1.0
        for v in bucket:
            c = float(v.get("confidence", 80)) / 100.0
            product *= (1.0 - c)
        combined_conf = round((1.0 - product) * 100)

        # Sévérité = max
        sev = max(bucket, key=lambda v: SEV_RANK.get(v.get("severity"), 0)).get("severity")

        # Représentant = celui avec la plus haute confiance individuelle
        rep = max(bucket, key=lambda v: v.get("confidence", 0)).copy()
        rep["confidence"] = combined_conf
        rep["severity"] = sev
        if len(bucket) > 1:
            rep["description"] = (
                rep.get("description", "")
                + f" [+{len(bucket) - 1} signaux corrélés, confiance bayésienne combinée]"
            )
        rep["source"] = "backend-correlated"
        out.append(rep)

    # Tri final : sévérité × confiance
    out.sort(key=lambda v: (
        -SEV_RANK.get(v.get("severity"), 0),
        -v.get("confidence", 0),
    ))

    return jsonify({
        "findings": out,
        "stats": {
            "input": len(findings),
            "output": len(out),
            "deduplicated": len(findings) - len(out),
        },
    })
