"""Tests des règles de chaining dans inference.py."""
from scanner.core.module_base import Finding
from scanner.core.inference import apply_inference


def test_chain_lfi_plus_log_poisoning_escalates_severity():
    """LFI + finding mentionnant un log → sévérité montée à critical."""
    findings = [
        Finding(type="path-traversal", severity="high",
                title="LFI sur ?page=", description="d", recommendation="r",
                url="u", confidence=90),
        Finding(type="info-disclosure", severity="low",
                title="Apache access log accessible",
                description="d", recommendation="r",
                url="u", evidence="access.log:...", confidence=80),
    ]
    apply_inference(findings)
    lfi = findings[0]
    assert lfi.severity == "critical"
    assert "RCE" in lfi.title or "chain" in lfi.description.lower()


def test_chain_open_redirect_plus_xss_escalates():
    findings = [
        Finding(type="open-redirect", severity="medium",
                description="d", recommendation="r",
                url="u", confidence=80),
        Finding(type="xss", severity="high",
                description="reflected xss", recommendation="r",
                url="u", confidence=85),
    ]
    apply_inference(findings)
    redirect = findings[0]
    assert redirect.severity == "high"


def test_chain_subdomain_plus_cookie_escalates():
    findings = [
        Finding(type="subdomain-found", severity="info",
                description="d", recommendation="r", url="u", confidence=100),
        Finding(type="insecure-cookie", severity="medium",
                description="d", recommendation="r", url="u", confidence=85),
    ]
    apply_inference(findings)
    cookie = next(f for f in findings if f.type == "insecure-cookie")
    assert cookie.severity == "high"


def test_no_chain_no_escalation():
    """Sans signal de chaining, les findings restent inchangés."""
    findings = [
        Finding(type="xss", severity="high",
                description="just xss alone", recommendation="r",
                url="u", confidence=80),
    ]
    apply_inference(findings)
    assert findings[0].severity == "high"
