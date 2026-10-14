# backend/tests/test_nosqli.py
def test_nosqli_detects_auth_bypass_via_status_change(mocker):
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=401, headers={}, text="invalid credentials")
    bypass = mocker.Mock(status_code=200, headers={}, text="welcome back")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [bypass] * 10)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/login"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings and findings[0].type == "nosqli" and findings[0].severity == "critical"
    assert findings[0].evidence_request is not None


def test_nosqli_detects_data_leak_via_body_growth(mocker):
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=200, headers={}, text="{}")  # ~2 bytes
    leak = mocker.Mock(status_code=200, headers={}, text="{" + '"user":"a",' * 50 + "}")  # much bigger
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [leak] * 10)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/search"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings


def test_nosqli_ignores_when_behavior_matches_baseline(mocker):
    """Même statut (toujours 401) et taille de corps dans la même bande (<20% d'écart) -> pas de finding."""
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=401, headers={}, text="invalid credentials, try again")
    same = mocker.Mock(status_code=401, headers={}, text="invalid credentials, retry please")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [same] * 10)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/login"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings == []


def test_nosqli_skips_endpoint_when_baseline_is_404(mocker):
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=404, headers={}, text="not found")
    mock_request = mocker.patch("scanner.core.http.requests.request", return_value=baseline)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/missing"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings == []
    assert mock_request.call_count == 1  # une seule requête : la baseline, puis on abandonne l'endpoint


def test_nosqli_returns_empty_without_api_endpoints():
    from scanner.modules.nosqli import NoSqliModule
    assert NoSqliModule().scan("http://example.com/", {}) == []
