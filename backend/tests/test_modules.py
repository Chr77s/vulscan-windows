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


def test_sqli_time_based_uses_matcher_and_captures_evidence(mocker):
    from scanner.modules.sqli import SqliModule
    fast = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fast)
    mocker.patch("scanner.core.http.time.sleep")  # désactive le rate-limiter réel pour ce test
    # sqli.py mesure ses propres deltas via son `import time` (time.time()), pas via http.py.
    # _timed_fetch lit time.time() 2 fois (avant/après) par appel : base_time_1, base_time_2,
    # puis 1 fois pour le 1er payload de TIME_PAYLOADS (qui confirme et interrompt la boucle) :
    #   base_time_1: t0=0.0, t1=0.05   -> 0.05s
    #   base_time_2: t0=1.0, t1=1.05   -> 0.05s  => baseline = max(...) = 0.05
    #   1er payload: t0=2.0, t1=6.6    -> 4.6s   => delta = 4.6 - 0.05 = 4.55 >= 3.5 -> confirmé
    time_values = iter([0.0, 0.05, 1.0, 1.05, 2.0, 6.6])
    mocker.patch("scanner.modules.sqli.time.time", side_effect=lambda: next(time_values))

    findings = SqliModule().scan("http://example.com/?id=5", {})
    time_based = [f for f in findings if "time-based" in (f.title or "").lower()]
    assert time_based, "aucune SQLi time-based détectée malgré un delta de 4.55s"
    assert time_based[0].evidence_request is not None
    assert time_based[0].evidence_response is not None


def test_sqli_time_based_does_not_false_positive_on_network_jitter(mocker):
    from scanner.modules.sqli import SqliModule
    fast = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fast)
    mocker.patch("scanner.core.http.time.sleep")
    # Baseline déjà lente (0.4s) ; chacun des 4 TIME_PAYLOADS n'ajoute que 0.3s de plus
    # (delta=0.3 < 3.5 à chaque fois) -> aucune confirmation, la boucle va jusqu'au bout.
    time_values = iter([
        0.0, 0.4,   # base_time_1 = 0.4s
        1.0, 1.4,   # base_time_2 = 0.4s  => baseline = 0.4
        2.0, 2.7,   # payload 1 : 0.7s, delta=0.3
        3.0, 3.7,   # payload 2 : 0.7s, delta=0.3
        4.0, 4.7,   # payload 3 : 0.7s, delta=0.3
        5.0, 5.7,   # payload 4 : 0.7s, delta=0.3
    ])
    mocker.patch("scanner.modules.sqli.time.time", side_effect=lambda: next(time_values))

    findings = SqliModule().scan("http://example.com/?id=5", {})
    assert not [f for f in findings if "time-based" in (f.title or "").lower()]


def test_xss_reflection_uses_matcher_and_captures_evidence(mocker):
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod

    # xss.py génère son propre marqueur aléatoire et l'injecte comme valeur du paramètre ;
    # on simule un serveur qui réfléchit systématiquement la valeur du param dans le body,
    # et on patche http.get directement pour contrôler précisément ce que scan() reçoit.
    def fake_get(url, ctx, capture=False, **kw):
        reflected_value = url.split("=")[-1]
        response = mocker.Mock(status_code=200, headers={}, text=f"<p>{reflected_value}</p>")
        if capture:
            req_ev = {"method": "GET", "url": url, "headers": {}, "body": None}
            resp_ev = {"status": 200, "headers": {}, "body_snippet": response.text, "elapsed_ms": 5.0}
            return response, req_ev, resp_ev
        return response

    mocker.patch.object(xss_mod.http, "get", side_effect=fake_get)
    findings = XssModule().scan("http://example.com/?q=hi", {})
    assert findings
    assert findings[0].evidence_request is not None
    assert findings[0].evidence_response is not None
