"""Tests du moteur d'inférence contextuelle."""
import pytest
from scanner.core.module_base import Finding
from scanner.core.inference import apply_inference


def test_xframe_neutralized_by_csp_ancestors():
    """X-Frame-Options manquant doit passer à info si CSP frame-ancestors observée."""
    findings = [
        Finding(type="missing-header", severity="medium",
                description="X-Frame-Options manquant",
                recommendation="rec", url="u",
                parameter="x-frame-options", confidence=80),
        Finding(type="weak-csp", severity="medium",
                description="CSP affaiblie",
                recommendation="rec", url="u",
                parameter="CSP",
                evidence="default-src 'self'; frame-ancestors 'self'",
                confidence=90),
    ]
    log = apply_inference(findings)
    xframe = next(f for f in findings if "x-frame" in f.parameter)
    assert xframe.severity == "info"
    assert any(c["rule"] == "xframe_neutralized_by_csp" for c in log["changes"])


def test_jwt_none_demotes_other_jwt_findings():
    """Si JWT alg=none détecté, les autres findings JWT passent en info."""
    findings = [
        Finding(type="jwt-weak", severity="critical",
                title="JWT avec algorithme 'none'",
                description="alg none", recommendation="r", url="u",
                confidence=100),
        Finding(type="jwt-weak", severity="low",
                title="JWT expiré",
                description="expired", recommendation="r", url="u",
                confidence=80),
    ]
    apply_inference(findings)
    expired = next(f for f in findings if "expir" in f.title.lower())
    assert expired.severity == "info"


def test_consolidate_low_sensitives():
    """Plus de 5 sensitive-data low → tous les surplus passent info."""
    findings = [
        Finding(type="sensitive-data", severity="low",
                description=f"email{i}@x.com",
                recommendation="r", url="u",
                confidence=70)
        for i in range(8)
    ]
    apply_inference(findings)
    infos = [f for f in findings if f.severity == "info"]
    # Le premier est gardé en low (consolidé), 7 autres en info
    assert len(infos) == 7


def test_inference_does_nothing_if_no_signals():
    """Sans signal contextuel → aucun changement."""
    findings = [
        Finding(type="xss", severity="high",
                description="d", recommendation="r", url="u", confidence=80),
    ]
    log = apply_inference(findings)
    # Aucune règle ne doit toucher ce finding isolé
    assert findings[0].severity == "high"
