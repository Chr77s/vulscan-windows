"""Tests des fonctions WAF (détection + mutation)."""


def test_detect_cloudflare_from_headers():
    from scanner.core.waf import detect_waf
    waf = detect_waf({"cf-ray": "abc123", "Server": "cloudflare"}, "")
    assert waf == "Cloudflare"


def test_detect_akamai_from_server():
    from scanner.core.waf import detect_waf
    waf = detect_waf({"Server": "AkamaiGHost"}, "")
    assert waf == "Akamai"


def test_detect_imperva_from_body():
    from scanner.core.waf import detect_waf
    body = "<html><body>Incapsula incident ID: 123-456</body></html>"
    waf = detect_waf({}, body)
    assert waf == "Imperva Incapsula"


def test_detect_no_waf():
    from scanner.core.waf import detect_waf
    assert detect_waf({"Server": "nginx"}, "Hello world") is None


def test_mutate_includes_original():
    from scanner.core.waf import mutate
    out = mutate("<script>alert(1)</script>")
    assert "<script>alert(1)</script>" in out


def test_mutate_case_variation():
    from scanner.core.waf import mutate
    out = mutate("script")
    assert any(s.lower() == "script" and s != "script" for s in out)


def test_mutate_url_encoding():
    from scanner.core.waf import mutate
    out = mutate("<script>")
    assert any("%3C" in s for s in out)


def test_mutate_sql_comment_injection():
    from scanner.core.waf import mutate
    out = mutate("OR 1=1")
    # On doit avoir au moins une variante avec /**/ injecté
    assert any("/**/" in s for s in out)
