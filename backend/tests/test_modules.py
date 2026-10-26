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
    # Régression pour "le matcher time-based doit comparer le DELTA (payload - baseline),
    # jamais le temps brut écoulé". Avec une baseline déjà lente (~3.2s, ex: réseau congestionné
    # ou cible distante) et des payloads à ~3.6s, le temps BRUT de chaque payload (3.6s) est déjà
    # ≥ TIME_THRESHOLD (3.5s) : une implémentation buguée qui comparerait le temps brut au lieu
    # du delta confirmerait ici à tort une SQLi time-based sur les 4 TIME_PAYLOADS. L'implémentation
    # correcte calcule delta = payload - baseline = 3.6 - 3.2 = 0.4s, largement sous le seuil
    # -> aucune confirmation, la boucle va jusqu'au bout des 4 payloads.
    time_values = iter([
        0.0, 3.2,    # base_time_1 = 3.2s
        10.0, 13.2,  # base_time_2 = 3.2s  => baseline = 3.2
        20.0, 23.6,  # payload 1 : brut=3.6s (>= seuil !), delta=0.4
        30.0, 33.6,  # payload 2 : brut=3.6s (>= seuil !), delta=0.4
        40.0, 43.6,  # payload 3 : brut=3.6s (>= seuil !), delta=0.4
        50.0, 53.6,  # payload 4 : brut=3.6s (>= seuil !), delta=0.4
    ])
    mocker.patch("scanner.modules.sqli.time.time", side_effect=lambda: next(time_values))

    findings = SqliModule().scan("http://example.com/?id=5", {})
    assert not [f for f in findings if "time-based" in (f.title or "").lower()]


def test_sqli_time_based_uses_catalog_payloads(mocker):
    """Le module doit consommer get_payloads('sqli', 'time_based'), pas sa constante en dur."""
    from scanner.modules.sqli import SqliModule
    import scanner.modules.sqli as sqli_mod

    spy = mocker.spy(sqli_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, headers={}, text="no error here")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    SqliModule().scan("http://a?id=1", {})

    calls = [c for c in spy.call_args_list if c.args and c.args[0] == "sqli"]
    assert any(c.kwargs.get("category") == "time_based" or (len(c.args) > 1 and c.args[1] == "time_based") for c in calls)


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


def test_lfi_uses_catalog_payloads_and_keeps_signature_field(mocker):
    """Le module doit lire payload+signature du catalogue, pas de PAYLOADS en dur."""
    from scanner.modules.lfi import LfiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="nothing interesting")
    confirming = mocker.Mock(status_code=200, headers={}, text="root:x:0:0:root:/root:/bin/bash")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 20)

    findings = LfiModule().scan("http://a?file=x", {})

    assert any(f.type == "path-traversal" and "../../../../etc/passwd" in f.payload for f in findings)


def test_ssrf_uses_catalog_payloads(mocker):
    from scanner.modules.ssrf import SsrfModule
    import scanner.modules.ssrf as ssrf_mod

    spy = mocker.spy(ssrf_mod, "get_payloads")
    baseline = mocker.Mock(status_code=200, headers={}, text="baseline body")
    mocker.patch("scanner.core.http.requests.request", return_value=baseline)
    mocker.patch("scanner.core.oob.OOBCanary.wait_for_hit", return_value=False)

    SsrfModule().scan("http://a?url=http://x", {})

    assert spy.call_args_list, "get_payloads n'a jamais été appelé — PAYLOADS en dur toujours utilisé ?"
    assert any(c.args and c.args[0] == "ssrf" for c in spy.call_args_list)


def test_xss_json_has_svg_and_img_context():
    from scanner.payloads import get_payloads
    assert get_payloads("xss", category="svg_context")
    assert get_payloads("xss", category="img_context")


def test_xss_module_selects_catalog_payload_for_detected_context(mocker):
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod
    from scanner.payloads import get_payloads as real_get_payloads
    from urllib.parse import urlparse, parse_qs

    # Payload sentinelle : s'il sort du finding, il vient forcément du catalogue.
    # Une table en dur donnerait "<script>alert(1)</script>" et ferait échouer le test.
    def fake_payloads(family, category=None, depth=None):
        if category == "html_context":
            return [{"payload": "SENTINEL_FROM_CATALOG", "category": category}]
        return real_get_payloads(family, category=category, depth=depth)

    spy = mocker.patch.object(xss_mod, "get_payloads", side_effect=fake_payloads)

    def fake_get(url, context, **kwargs):
        # Le module génère son marqueur par requête : on le relit dans l'URL et on le réfléchit.
        marker = parse_qs(urlparse(url).query)["q"][0]
        resp = mocker.Mock(status_code=200, headers={}, text=f"<div>{marker}</div>")
        return resp, {}, {}
    mocker.patch("scanner.core.http.get", side_effect=fake_get)

    findings = XssModule().scan("http://a?q=test", {})

    assert findings, "aucun finding : la réflexion n'a pas été détectée, le catalogue n'a jamais été consulté"
    assert findings[0].payload == "SENTINEL_FROM_CATALOG"
    assert any(c.kwargs.get("category") == "html_context" for c in spy.call_args_list)


def test_xss_confirms_second_catalog_payload_not_first(mocker):
    """Si seul le 2e payload du catalogue reflète sans échappement, le finding doit le retenir (pas items[0])."""
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod
    from scanner.payloads import get_payloads as real_get_payloads
    from urllib.parse import urlparse, parse_qs

    catalog_items = [
        {"payload": "XSS_FIRST_NEVER_CONFIRMS", "category": "html_context"},
        {"payload": "XSS_SECOND_CONFIRMS", "category": "html_context"},
        {"payload": "XSS_THIRD_NEVER_TRIED", "category": "html_context"},
    ]

    def fake_payloads(family, category=None, depth=None):
        if category == "html_context":
            return catalog_items
        return real_get_payloads(family, category=category, depth=depth)

    mocker.patch.object(xss_mod, "get_payloads", side_effect=fake_payloads)

    def fake_get(url, context, capture=False, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        if value == "XSS_FIRST_NEVER_CONFIRMS":
            body = "<div>&lt;escaped&gt;</div>"  # échappé : ne confirme pas
        else:
            body = f"<div>{value}</div>"  # marqueur + 2e payload : reflet verbatim
        resp = mocker.Mock(status_code=200, headers={}, text=body)
        if capture:
            return resp, {"method": "GET", "url": url}, {"status": 200, "body_snippet": body}
        return resp

    mocker.patch("scanner.core.http.get", side_effect=fake_get)

    findings = XssModule().scan("http://a?q=test", {})

    assert findings
    assert findings[0].payload == "XSS_SECOND_CONFIRMS"
    assert findings[0].confidence == 95
    assert findings[0].detection_method == "payload-confirmed-unescaped"


def test_xss_falls_back_to_marker_evidence_when_nothing_confirms(mocker):
    """Si aucun payload du catalogue ne reflète sans échappement, on retrouve le comportement actuel."""
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod
    from scanner.payloads import get_payloads as real_get_payloads
    from urllib.parse import urlparse, parse_qs

    catalog_items = [
        {"payload": "XSS_FIRST_ITEM", "category": "html_context"},
        {"payload": "XSS_SECOND_ITEM", "category": "html_context"},
    ]

    def fake_payloads(family, category=None, depth=None):
        if category == "html_context":
            return catalog_items
        return real_get_payloads(family, category=category, depth=depth)

    mocker.patch.object(xss_mod, "get_payloads", side_effect=fake_payloads)

    def fake_get(url, context, capture=False, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        if value.startswith("XSS_"):
            body = "<div>&lt;escaped&gt;</div>"  # jamais reflété tel quel
        else:
            body = f"<div>{value}</div>"  # marqueur : reflet verbatim (détection initiale)
        resp = mocker.Mock(status_code=200, headers={}, text=body)
        if capture:
            return resp, {"method": "GET", "url": url}, {"status": 200, "body_snippet": body}
        return resp

    mocker.patch("scanner.core.http.get", side_effect=fake_get)

    findings = XssModule().scan("http://a?q=test", {})

    assert findings
    assert findings[0].confidence == 85
    assert findings[0].detection_method == "reflection-marker"
    assert findings[0].payload == "XSS_FIRST_ITEM"


def test_xss_threads_depth_into_confirmation_loop(mocker):
    """depth doit être transmis à get_payloads par la boucle de confirmation, pas seulement par _payload_catalog."""
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod
    from urllib.parse import urlparse, parse_qs

    def fake_get(url, context, capture=False, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        body = f"<div>{value}</div>"  # tout reflète verbatim
        resp = mocker.Mock(status_code=200, headers={}, text=body)
        if capture:
            return resp, {"method": "GET", "url": url}, {"status": 200, "body_snippet": body}
        return resp

    mocker.patch("scanner.core.http.get", side_effect=fake_get)
    spy = mocker.spy(xss_mod, "get_payloads")

    XssModule().scan("http://a?q=test", {"depth": "basic"})
    calls_basic = [c for c in spy.call_args_list
                   if c.args and c.args[0] == "xss" and c.kwargs.get("category") == "html_context"]
    assert len(calls_basic) >= 2, (
        "get_payloads(category=html_context) doit être appelé à la fois par _payload_catalog "
        "ET par la boucle de confirmation"
    )
    assert all(c.kwargs.get("depth") == "basic" for c in calls_basic)

    spy.reset_mock()
    XssModule().scan("http://a?q=test", {})
    calls_none = [c for c in spy.call_args_list
                  if c.args and c.args[0] == "xss" and c.kwargs.get("category") == "html_context"]
    assert len(calls_none) >= 2
    assert all(c.kwargs.get("depth") is None for c in calls_none)


def test_xss_does_not_confirm_when_payload_stays_inside_quoted_attribute(mocker):
    """Un payload reflété verbatim ne suffit pas : s'il reste emprisonné dans l'attribut quoté
    (aucun guillemet dans le payload pour casser la chaîne), ce n'est pas une vraie confirmation —
    il faut retomber sur le fallback marker-reflection (85%), pas payload-confirmed-unescaped (95%)."""
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod
    from scanner.payloads import get_payloads as real_get_payloads
    from urllib.parse import urlparse, parse_qs

    # Aucun caractère de guillemet : ne casse jamais un attribut quoté, même reflété tel quel.
    NO_QUOTE_PAYLOAD = " autofocus onfocus=alert(1) x="

    def fake_payloads(family, category=None, depth=None):
        if category == "attribute_context":
            return [{"payload": NO_QUOTE_PAYLOAD, "category": category}]
        return real_get_payloads(family, category=category, depth=depth)

    mocker.patch.object(xss_mod, "get_payloads", side_effect=fake_payloads)

    def fake_get(url, context, capture=False, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        # Le marqueur ET le payload de confirmation sont tous deux reflétés verbatim,
        # mais toujours contenus dans un attribut correctement quoté (jamais sorti des guillemets).
        body = f'<input value="{value}">'
        resp = mocker.Mock(status_code=200, headers={}, text=body)
        if capture:
            return resp, {"method": "GET", "url": url}, {"status": 200, "body_snippet": body}
        return resp

    mocker.patch("scanner.core.http.get", side_effect=fake_get)

    findings = XssModule().scan("http://a?q=test", {})

    assert findings
    assert findings[0].confidence == 85
    assert findings[0].detection_method == "reflection-marker"


def test_xss_confirms_when_payload_actually_breaks_out_of_quoted_attribute(mocker):
    """Contrôle : un payload qui CONTIENT le guillemet de l'attribut doit toujours confirmer à 95%."""
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod
    from scanner.payloads import get_payloads as real_get_payloads
    from urllib.parse import urlparse, parse_qs

    BREAKOUT_PAYLOAD = '" onmouseover="alert(1)'  # contient le guillemet : casse l'attribut

    def fake_payloads(family, category=None, depth=None):
        if category == "attribute_context":
            return [{"payload": BREAKOUT_PAYLOAD, "category": category}]
        return real_get_payloads(family, category=category, depth=depth)

    mocker.patch.object(xss_mod, "get_payloads", side_effect=fake_payloads)

    def fake_get(url, context, capture=False, **kwargs):
        value = parse_qs(urlparse(url).query).get("q", [""])[0]
        body = f'<input value="{value}">'
        resp = mocker.Mock(status_code=200, headers={}, text=body)
        if capture:
            return resp, {"method": "GET", "url": url}, {"status": 200, "body_snippet": body}
        return resp

    mocker.patch("scanner.core.http.get", side_effect=fake_get)

    findings = XssModule().scan("http://a?q=test", {})

    assert findings
    assert findings[0].confidence == 95
    assert findings[0].detection_method == "payload-confirmed-unescaped"
    assert findings[0].payload == BREAKOUT_PAYLOAD


def test_command_injection_uses_catalog(mocker):
    from scanner.modules.command_injection import CommandInjectionModule
    import scanner.modules.command_injection as ci_mod

    spy = mocker.spy(ci_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, headers={}, text="no match")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    CommandInjectionModule().scan("http://a?cmd=ls", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"


def test_xxe_uses_catalog_payloads(mocker):
    from scanner.modules.xxe import XxeModule
    import scanner.modules.xxe as xxe_mod

    spy = mocker.spy(xxe_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, headers={}, text="no doctype error here")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    XxeModule().scan("http://a/api.xml", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"


def test_xxe_still_detects_file_scheme_reflection(mocker):
    from scanner.modules.xxe import XxeModule
    fake = mocker.Mock(status_code=200, headers={}, text="leaked: file:///etc/hostname contents here")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    findings = XxeModule().scan("http://a/api.xml", {})
    assert any(f.type == "xxe" and f.severity == "critical" for f in findings)


def test_header_injection_uses_catalog(mocker):
    from scanner.modules.header_injection import HeaderInjectionModule
    import scanner.modules.header_injection as hi_mod

    spy = mocker.spy(hi_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    HeaderInjectionModule().scan("http://a", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"


def test_json_fuzzer_pulls_extra_sqli_and_lfi_payloads(mocker):
    from scanner.modules.json_fuzzer import JsonFuzzerModule
    import scanner.modules.json_fuzzer as jf_mod

    spy = mocker.spy(jf_mod, "get_payloads")
    r_base = mocker.Mock(status_code=200, text="{}")
    mocker.patch("scanner.core.http.requests.request", return_value=r_base)

    JsonFuzzerModule().scan("http://a/api/x", {"crawled": {"api_endpoints": ["http://a/api/x"]}})
    families_called = {c.args[0] for c in spy.call_args_list if c.args}
    assert families_called >= {"sqli", "lfi"}


def test_form_fuzzer_pulls_extra_sqli_and_lfi_payloads(mocker):
    from scanner.modules.form_fuzzer import FormFuzzerModule
    import scanner.modules.form_fuzzer as ff_mod

    spy = mocker.spy(ff_mod, "get_payloads")
    mocker.patch("scanner.core.http.post", return_value=mocker.Mock(text="ok"))
    mocker.patch("scanner.core.http.get", return_value=mocker.Mock(text="ok"))

    form = {"action": "http://a/submit", "method": "POST",
            "fields": [{"name": "comment", "type": "text", "value": ""}]}
    FormFuzzerModule().scan("http://a", {"crawled": {"forms": [form]}})
    families_called = {c.args[0] for c in spy.call_args_list if c.args}
    assert families_called >= {"sqli", "lfi"}
