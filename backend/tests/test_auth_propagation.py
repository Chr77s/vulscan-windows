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
