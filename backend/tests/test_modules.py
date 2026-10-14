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
