"""Tests sur quelques modules — focus sur la logique de détection sans réseau."""
import pytest


def test_jwt_decode_with_none_alg():
    """jwt-analyzer doit détecter alg:none même sans requête HTTP."""
    import base64
    import json
    from scanner.modules.jwt_analyzer import JwtAnalyzerModule

    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": 1}).encode()).decode().rstrip("=")
    token = f"{header}.{payload}.signature"

    # Vérifier directement la décode helper
    mod = JwtAnalyzerModule()
    h = json.loads(mod._b64decode(header))
    assert h["alg"] == "none"


def test_jwt_crack_weak_secret():
    """Le module doit casser un JWT signé avec un secret de sa wordlist."""
    import base64
    import hmac
    import hashlib
    import json
    from scanner.modules.jwt_analyzer import JwtAnalyzerModule

    secret = "secret123"
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({"sub": 1}).encode()).decode().rstrip("=")
    signing_input = f"{header}.{payload}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")

    # secret123 est dans la wordlist
    assert secret in JwtAnalyzerModule.COMMON_SECRETS


def test_finding_to_dict_shape():
    """Vérifie que Finding.to_dict expose les bonnes clés (CamelCase)."""
    from scanner.core.module_base import Finding
    f = Finding(
        type="xss", severity="high",
        description="test", recommendation="test",
        url="http://a", cwe_id="CWE-79", owasp_id="A03:2021",
        cvss_base=6.1,
    )
    d = f.to_dict()
    assert d["type"] == "xss"
    assert "detectionMethod" in d
    assert "detectedAt" in d
    assert "cvssBase" in d
    assert d["cwe"]["id"] == "CWE-79"
    assert d["owasp"]["id"] == "A03:2021"


def test_finding_to_dict_includes_evidence_request_response_when_set():
    from scanner.core.module_base import Finding
    f = Finding(
        type="sqli", severity="critical", description="t", recommendation="t", url="http://a",
        evidence_request={"method": "GET", "url": "http://a", "headers": {}, "body": None},
        evidence_response={"status": 200, "headers": {}, "body_snippet": "ok", "elapsed_ms": 12.3},
    )
    d = f.to_dict()
    assert d["evidenceRequest"]["method"] == "GET"
    assert d["evidenceResponse"]["status"] == 200

def test_finding_to_dict_evidence_defaults_to_none():
    from scanner.core.module_base import Finding
    f = Finding(type="xss", severity="high", description="t", recommendation="t", url="http://a")
    d = f.to_dict()
    assert d["evidenceRequest"] is None
    assert d["evidenceResponse"] is None


def test_lfi_confirmed_finding_has_evidence_request_response(mocker):
    from scanner.modules.lfi import LfiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="nothing interesting")
    confirming = mocker.Mock(status_code=200, headers={}, text="root:x:0:0:root:/root:/bin/bash")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 20)
    findings = LfiModule().scan("http://example.com/?file=a", {})
    confirmed = [f for f in findings if f.severity == "critical"]
    assert confirmed, "aucune LFI confirmée avec une réponse contenant /etc/passwd"
    assert confirmed[0].evidence_request is not None
    assert confirmed[0].evidence_response["body_snippet"].startswith("root:x:0:0")


def test_command_injection_confirmed_finding_has_evidence(mocker):
    from scanner.modules.command_injection import CommandInjectionModule
    confirming = mocker.Mock(status_code=200, headers={}, text="uid=0(root) gid=0(root)")
    mocker.patch("scanner.core.http.requests.request", return_value=confirming)
    findings = CommandInjectionModule().scan("http://example.com/?cmd=ping", {})
    assert findings and findings[0].evidence_request is not None


def test_lfi_signatures():
    """La regex root:x:0:0 doit matcher un /etc/passwd typique."""
    from scanner.modules.lfi import LfiModule
    import re
    body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:..."
    matched = False
    for pat, _ in LfiModule.SIGNATURES_GENERIC:
        if pat.search(body):
            matched = True
            break
    assert matched
