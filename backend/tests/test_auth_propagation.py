from tests.conftest import assert_module_propagates_auth


def test_headers_module_propagates_auth(mocker):
    from scanner.modules.headers import HeadersModule
    assert_module_propagates_auth(mocker, HeadersModule, "http://example.com/")


def test_cors_misconfig_module_propagates_auth(mocker):
    from scanner.modules.cors_misconfig import CorsMisconfigModule
    assert_module_propagates_auth(mocker, CorsMisconfigModule, "http://example.com/")


def test_info_disclosure_module_propagates_auth(mocker):
    from scanner.modules.info_disclosure import InfoDisclosureModule
    assert_module_propagates_auth(mocker, InfoDisclosureModule, "http://example.com/")


def test_jwt_analyzer_module_propagates_auth(mocker):
    from scanner.modules.jwt_analyzer import JwtAnalyzerModule
    assert_module_propagates_auth(mocker, JwtAnalyzerModule, "http://example.com/")


def test_rate_limit_module_propagates_auth(mocker):
    from scanner.modules.rate_limit import RateLimitModule
    assert_module_propagates_auth(mocker, RateLimitModule, "http://example.com/login")


def test_form_fuzzer_module_propagates_auth(mocker):
    from scanner.modules.form_fuzzer import FormFuzzerModule
    forms = [{"action": "http://example.com/comment", "method": "POST",
              "fields": [{"name": "body", "type": "text", "value": ""}], "id": ""}]
    assert_module_propagates_auth(mocker, FormFuzzerModule, "http://example.com/",
                                   extra_context={"crawled": {"forms": forms}})


def test_header_injection_module_propagates_auth(mocker):
    from scanner.modules.header_injection import HeaderInjectionModule
    assert_module_propagates_auth(mocker, HeaderInjectionModule, "http://example.com/")


def test_json_fuzzer_module_propagates_auth(mocker):
    from scanner.modules.json_fuzzer import JsonFuzzerModule
    assert_module_propagates_auth(mocker, JsonFuzzerModule, "http://example.com/api/items")


def test_param_discovery_module_propagates_auth(mocker):
    from scanner.modules.param_discovery import ParamDiscoveryModule
    assert_module_propagates_auth(mocker, ParamDiscoveryModule, "http://example.com/")


def test_graphql_module_propagates_auth(mocker):
    from scanner.modules.graphql import GraphQLModule
    assert_module_propagates_auth(mocker, GraphQLModule, "http://example.com/graphql")


def test_file_exposure_module_propagates_auth(mocker):
    from scanner.modules.file_exposure import FileExposureModule
    assert_module_propagates_auth(mocker, FileExposureModule, "http://example.com/")


def test_dir_bruteforce_module_propagates_auth(mocker):
    from scanner.modules.dir_bruteforce import DirBruteforceModule
    assert_module_propagates_auth(mocker, DirBruteforceModule, "http://example.com/")


def test_tech_fingerprint_module_propagates_auth(mocker):
    from scanner.modules.tech_fingerprint import TechFingerprintModule
    assert_module_propagates_auth(mocker, TechFingerprintModule, "http://example.com/")


def test_waf_detect_module_propagates_auth(mocker):
    from scanner.modules.waf_detect import WafDetectModule
    assert_module_propagates_auth(mocker, WafDetectModule, "http://example.com/")


def test_race_conditions_module_propagates_auth(mocker):
    from scanner.modules.race_conditions import RaceConditionsModule
    forms = [{"action": "http://example.com/vote", "method": "POST",
              "fields": [{"name": "choice", "type": "text", "value": "1"}], "id": ""}]
    assert_module_propagates_auth(mocker, RaceConditionsModule, "http://example.com/",
                                   extra_context={"crawled": {"forms": forms}})


def test_subdomain_enum_never_sends_auth_header_to_crtsh(mocker):
    """subdomain_enum ne passe par scanner.core.http pour rien (aucun HTTP vers la cible) ;
    son unique appel réseau (crt.sh, service tiers) ne doit jamais recevoir le Bearer/cookie
    de la cible — comportement déjà correct aujourd'hui, ce test le fige."""
    from scanner.modules.subdomain_enum import SubdomainEnumModule
    mocker.patch("socket.gethostbyname", side_effect=OSError("no DNS in tests"))
    fake = mocker.Mock(ok=True, json=lambda: [])
    mock_via_http_module = mocker.patch("scanner.core.http.requests.request")
    mock_crtsh = mocker.patch("scanner.modules.subdomain_enum.requests.get", return_value=fake)
    ctx = {"auth": {"headers": {"Authorization": "Bearer SHOULD-NOT-LEAK"}}}
    SubdomainEnumModule().scan("http://example.com/", ctx)
    mock_via_http_module.assert_not_called()
    assert mock_crtsh.called
    assert "Authorization" not in (mock_crtsh.call_args.kwargs.get("headers") or {})
