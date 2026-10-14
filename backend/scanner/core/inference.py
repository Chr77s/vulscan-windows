"""
Moteur d'inférence contextuelle.

Une fois que tous les modules ont produit leurs findings, on applique des
**règles contextuelles** qui regardent l'ensemble pour ajuster confiance/sévérité.

Exemple : si on a détecté un CSRF (medium) ET qu'on observe par ailleurs
des cookies avec SameSite=Strict, alors le CSRF n'est probablement pas exploitable
→ on baisse la confiance et la sévérité à low.

Toutes les règles sont déclaratives et inspectables (pas de magie ML).
"""
from __future__ import annotations
from typing import List, Dict, Any, Callable
from .module_base import Finding


# Table : (predicate, action, reason)
# - predicate(findings, idx) -> bool : la règle s'applique-t-elle au finding à idx ?
# - action(finding, findings) -> finding modifié
# - reason : explication ajoutée à `evidence`


def _has_finding(findings: List[Finding], type_: str, parameter_contains: str = None) -> Finding | None:
    for f in findings:
        if f.type == type_:
            if parameter_contains:
                if parameter_contains.lower() in (f.parameter or "").lower():
                    return f
            else:
                return f
    return None


def _has_evidence_containing(findings: List[Finding], type_: str, text: str) -> Finding | None:
    """Cherche un finding du type donné dont l'evidence contient text (case-insensitive)."""
    text_l = text.lower()
    for f in findings:
        if f.type == type_ and text_l in (f.evidence or "").lower():
            return f
    return None


# =============================================================
# RÈGLES
# =============================================================

def rule_csrf_neutralized_by_samesite(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Si un CSRF est détecté ET qu'on observe Set-Cookie avec SameSite=Strict
    pour un cookie de session, la confiance du CSRF chute drastiquement
    car le cookie n'accompagne pas une requête cross-site.
    """
    changes = []
    samesite_strict = _has_evidence_containing(findings, "insecure-cookie", "samesite=strict") or \
                      None
    # Note : insecure-cookie est émis QUAND samesite manque, pas quand il est strict.
    # On regarde donc un signal externe :
    # une absence de finding "insecure-cookie" + le scan a inspecté les cookies = bonne config
    has_cookie_audit = any(f.type == "insecure-cookie" for f in findings) or \
                       any("Set-Cookie" in (f.parameter or "") for f in findings)

    if samesite_strict or not has_cookie_audit:
        # Pas de SameSite Strict observé ou pas d'audit cookie : on n'agit pas
        return changes

    for f in findings:
        if f.type == "csrf" and f.confidence >= 50:
            old_conf, old_sev = f.confidence, f.severity
            f.confidence = max(20, f.confidence - 40)
            f.severity = "low"
            changes.append({
                "rule": "csrf_neutralized_by_samesite",
                "finding_id": f.id,
                "before": {"confidence": old_conf, "severity": old_sev},
                "after":  {"confidence": f.confidence, "severity": f.severity},
                "reason": "SameSite=Strict observé — cookie ne sera pas envoyé sur requête cross-site.",
            })
    return changes


def rule_xframe_neutralized_by_csp_ancestors(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Si X-Frame-Options manque MAIS qu'une CSP frame-ancestors est observée,
    le clickjacking est déjà protégé → ignorer le finding header.
    """
    changes = []
    csp_with_ancestors = None
    for f in findings:
        if f.type == "missing-header" or f.type == "weak-csp":
            if "frame-ancestors" in (f.evidence or "").lower():
                csp_with_ancestors = f
                break

    if not csp_with_ancestors:
        return changes

    for f in findings:
        if f.type == "missing-header" and "x-frame-options" in (f.parameter or "").lower():
            old_sev = f.severity
            f.severity = "info"
            f.confidence = 30
            f.description += " [Note : CSP frame-ancestors observée — clickjacking déjà protégé.]"
            changes.append({
                "rule": "xframe_neutralized_by_csp",
                "finding_id": f.id,
                "before": {"severity": old_sev},
                "after":  {"severity": f.severity},
                "reason": "CSP frame-ancestors présente — X-Frame-Options redondant.",
            })
    return changes


def rule_outdated_lib_softened_by_csp(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Si une lib JS obsolète vulnérable XSS est détectée MAIS qu'on a une CSP
    stricte (pas de unsafe-inline ni unsafe-eval), l'exploitation XSS est très
    réduite → baisse la sévérité d'un cran.
    """
    changes = []
    strong_csp = False
    for f in findings:
        if f.type in ("missing-header", "weak-csp"):
            ev = (f.evidence or "").lower()
            # CSP présente sans faille typique
            if ev and "unsafe-inline" not in ev and "unsafe-eval" not in ev and "*" not in ev[:200]:
                strong_csp = True
                break

    if not strong_csp:
        return changes

    sev_drop = {"critical": "high", "high": "medium", "medium": "low", "low": "info"}
    for f in findings:
        if f.type == "outdated-library" and "xss" in (f.description or "").lower():
            old_sev = f.severity
            new_sev = sev_drop.get(f.severity, f.severity)
            if new_sev != old_sev:
                f.severity = new_sev
                f.confidence = max(40, f.confidence - 20)
                changes.append({
                    "rule": "outdated_lib_softened_by_csp",
                    "finding_id": f.id,
                    "before": {"severity": old_sev},
                    "after":  {"severity": f.severity},
                    "reason": "CSP stricte limite drastiquement l'exploitation XSS via cette lib.",
                })
    return changes


def rule_jwt_none_blocks_other_jwt_findings(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Si on a déjà un JWT alg=none confirmé (critical), les autres findings JWT
    (expiré, etc.) deviennent du bruit → les baisser à info.
    """
    changes = []
    has_critical_jwt = any(
        f.type == "jwt-weak" and f.severity == "critical" and "none" in (f.title or "").lower()
        for f in findings
    )
    if not has_critical_jwt:
        return changes
    for f in findings:
        if f.type == "jwt-weak" and f.severity != "critical":
            old_sev = f.severity
            f.severity = "info"
            f.confidence = max(30, f.confidence - 30)
            changes.append({
                "rule": "jwt_none_blocks_other_jwt",
                "finding_id": f.id,
                "before": {"severity": old_sev},
                "after":  {"severity": "info"},
                "reason": "alg=none déjà détecté — autres signaux JWT redondants en priorité.",
            })
    return changes


def rule_high_count_sensitive_data_consolidation(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Si on a > 5 findings sensitive-data low (emails par ex.), les regrouper
    en 1 seul finding "Multiple sensitive data exposure" et masquer les autres.
    """
    changes = []
    low_sensitives = [f for f in findings if f.type == "sensitive-data" and f.severity == "low"]
    if len(low_sensitives) > 5:
        # Garde le premier, masque les autres
        kept = low_sensitives[0]
        kept.title = f"Sensitive data exposure (×{len(low_sensitives)} occurrences)"
        for f in low_sensitives[1:]:
            f.severity = "info"
            f.confidence = max(20, f.confidence - 40)
            changes.append({
                "rule": "consolidate_low_sensitives",
                "finding_id": f.id,
                "before": {"severity": "low"},
                "after":  {"severity": "info"},
                "reason": f"Consolidé dans le finding parent ({len(low_sensitives)} similaires).",
            })
    return changes


# ============================================================
# RÈGLES DE CHAINING — élèvent la sévérité quand vulns se combinent
# ============================================================

def rule_chain_lfi_plus_log_poisoning(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    LFI + control sur log (User-Agent dans un fichier log accessible)
    = potentiel RCE via log poisoning. On crée un finding "chain".
    """
    changes = []
    has_lfi = any(f.type == "path-traversal" and f.severity in ("critical", "high") for f in findings)
    has_logging = any(
        f.type == "info-disclosure" and ("log" in (f.title or "").lower() or "log" in (f.evidence or "").lower())
        for f in findings
    )
    if has_lfi and has_logging:
        lfi = next(f for f in findings if f.type == "path-traversal")
        old_sev = lfi.severity
        lfi.severity = "critical"
        lfi.confidence = min(100, lfi.confidence + 10)
        lfi.title = (lfi.title or "LFI") + " + log poisoning potentiel = RCE"
        lfi.description += (
            " [CHAIN DÉTECTÉE : combinée à un fichier log accessible via le même LFI, "
            "cette vuln peut être escaladée en RCE via injection d'un payload PHP "
            "dans User-Agent → lecture du log via LFI.]"
        )
        lfi.cvss_base = 9.8
        changes.append({
            "rule": "chain_lfi_plus_log_poisoning",
            "finding_id": lfi.id,
            "before": {"severity": old_sev},
            "after": {"severity": "critical", "chain": "LFI + log = RCE"},
            "reason": "LFI exploitable + accès à un fichier log → injection User-Agent → RCE.",
        })
    return changes


def rule_chain_open_redirect_plus_xss(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Open Redirect + XSS reflected = exploitation cross-domain plus crédible
    (l'URL légitime sert de levier d'attaque).
    """
    changes = []
    has_redirect = any(f.type == "open-redirect" for f in findings)
    has_xss = any(f.type == "xss" and f.severity in ("high", "critical") for f in findings)
    if has_redirect and has_xss:
        redirect = next(f for f in findings if f.type == "open-redirect")
        old_sev = redirect.severity
        if redirect.severity != "high":
            redirect.severity = "high"
            redirect.confidence = min(100, redirect.confidence + 15)
            redirect.description += (
                " [CHAIN : combiné avec un XSS reflected, l'open redirect permet de "
                "rediriger vers une page sous contrôle de l'attaquant qui exécute du JS, "
                "tout en gardant l'URL d'origine légitime — vecteur de phishing crédible.]"
            )
            changes.append({
                "rule": "chain_open_redirect_plus_xss",
                "finding_id": redirect.id,
                "before": {"severity": old_sev},
                "after": {"severity": "high", "chain": "Open Redirect + XSS"},
                "reason": "Open redirect amplifié par XSS reflected sur même domaine.",
            })
    return changes


def rule_chain_subdomain_plus_cookie_scope(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Subdomain découverts + cookies sans Domain restrictif = risque de subdomain takeover
    → vol de session.
    """
    changes = []
    has_subdomains = any(f.type == "subdomain-found" for f in findings)
    has_insecure_cookie = any(f.type == "insecure-cookie" for f in findings)
    if has_subdomains and has_insecure_cookie:
        cookie = next(f for f in findings if f.type == "insecure-cookie")
        old_sev = cookie.severity
        if cookie.severity in ("low", "medium"):
            cookie.severity = "high"
            cookie.confidence = min(100, cookie.confidence + 10)
            cookie.description += (
                " [CHAIN : combiné avec plusieurs sous-domaines actifs, un cookie sans Domain "
                "strict est volable si l'un des sous-domaines est compromis (subdomain takeover).]"
            )
            changes.append({
                "rule": "chain_subdomain_plus_cookie",
                "finding_id": cookie.id,
                "before": {"severity": old_sev},
                "after": {"severity": "high"},
                "reason": "Surface multi-host + cookie partagé = vol de session probable.",
            })
    return changes


def rule_chain_missing_sri_plus_mixed_content(findings: List[Finding]) -> List[Dict[str, Any]]:
    """
    Pas de SRI sur scripts CDN + Mixed Content = MITM peut injecter du JS.
    """
    changes = []
    has_sri = any(f.type == "missing-sri" for f in findings)
    has_mixed = any(f.type == "mixed-content" for f in findings)
    if has_sri and has_mixed:
        sri = next(f for f in findings if f.type == "missing-sri")
        old_sev = sri.severity
        if sri.severity != "high":
            sri.severity = "high"
            sri.confidence = min(100, sri.confidence + 15)
            sri.description += (
                " [CHAIN : combiné avec du mixed content HTTPS+HTTP, un attaquant MITM "
                "peut remplacer le script CDN sans intégrité par du JS malveillant.]"
            )
            changes.append({
                "rule": "chain_sri_plus_mixed",
                "finding_id": sri.id,
                "before": {"severity": old_sev},
                "after": {"severity": "high"},
                "reason": "Mixed content + missing SRI = injection JS exploitable en MITM.",
            })
    return changes


# Liste de toutes les règles à appliquer (ordre = importance)
ALL_RULES: List[Callable[[List[Finding]], List[Dict[str, Any]]]] = [
    # Règles d'atténuation
    rule_csrf_neutralized_by_samesite,
    rule_xframe_neutralized_by_csp_ancestors,
    rule_outdated_lib_softened_by_csp,
    rule_jwt_none_blocks_other_jwt_findings,
    rule_high_count_sensitive_data_consolidation,
    # Règles d'amplification (chaining)
    rule_chain_lfi_plus_log_poisoning,
    rule_chain_open_redirect_plus_xss,
    rule_chain_subdomain_plus_cookie_scope,
    rule_chain_missing_sri_plus_mixed_content,
]


def apply_inference(findings: List[Finding]) -> Dict[str, Any]:
    """
    Applique toutes les règles d'inférence sur la liste de findings (in-place).
    Retourne un journal des ajustements pour traçabilité.
    """
    all_changes = []
    for rule in ALL_RULES:
        try:
            changes = rule(findings)
            all_changes.extend(changes)
        except Exception as e:
            all_changes.append({"rule": rule.__name__, "error": str(e)})
    return {"applied_rules": len(ALL_RULES), "changes": all_changes}
