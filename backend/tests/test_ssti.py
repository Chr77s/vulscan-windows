# backend/tests/test_ssti.py
def test_ssti_confirms_jinja2_when_calculation_reflected(mocker):
    from scanner.modules.ssti import SstiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="<p>hello</p>")
    confirming = mocker.Mock(status_code=200, headers={}, text="<p>result: 9801547</p>")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 10)
    findings = SstiModule().scan("http://example.com/?name=hi", {})
    assert findings and findings[0].type == "ssti" and findings[0].severity == "critical"
    assert findings[0].evidence_request is not None


def test_ssti_ignores_when_expected_value_already_in_baseline(mocker):
    """Si la baseline contient déjà '9801547' (coïncidence très improbable mais testée quand
    même pour la symétrie avec l'ancien oracle), pas de faux positif."""
    from scanner.modules.ssti import SstiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="<p>ref: 9801547</p>")
    confirming = mocker.Mock(status_code=200, headers={}, text="<p>ref: 9801547</p>")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 10)
    findings = SstiModule().scan("http://example.com/?name=hi", {})
    assert findings == []


def test_ssti_ignores_coincidental_49_substring_without_7_digit_oracle(mocker):
    """L'ancien oracle à 2 chiffres ('49') faussait positif sur des pages portant un token
    aléatoire ou un prix ('$49.99', 'Age: 49'...). La baseline ET la réponse sondée partagent
    ici un '49' coïncidentel, mais seul le nouvel oracle à 7 chiffres ('9801547') fait foi :
    comme il n'apparaît dans aucune des deux, aucun finding ne doit être produit."""
    from scanner.modules.ssti import SstiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="<p>Age: 49</p>")
    probed = mocker.Mock(status_code=200, headers={}, text="<p>Age: 49</p>")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [probed] * 10)
    findings = SstiModule().scan("http://example.com/?name=hi", {})
    assert findings == []


def test_ssti_fetches_baseline_exactly_once_regardless_of_probe_count(mocker):
    """La baseline est récupérée une seule fois puis réutilisée pour les 4 sondes du même
    paramètre — jamais re-fetchée à chaque essai. Si elle l'était, une page qui n'est pas
    parfaitement déterministe d'une requête à l'autre (timestamp, nonce, compteur) pourrait
    faire croire à tort que '49' est absent de "la" baseline alors qu'il ne l'était que de
    CETTE requête-ci — un seul fetch, comparé à toutes les sondes, évite ce piège."""
    from scanner.modules.ssti import SstiModule
    import scanner.modules.ssti as ssti_mod
    response = mocker.Mock(status_code=200, headers={}, text="<p>hello</p>")

    def fake_get(url, ctx, capture=False, **kw):
        if capture:
            req_ev = {"method": "GET", "url": url, "headers": {}, "body": None}
            resp_ev = {"status": 200, "headers": {}, "body_snippet": "hello", "elapsed_ms": 1.0}
            return response, req_ev, resp_ev
        return response

    mock_get = mocker.patch.object(ssti_mod.http, "get", side_effect=fake_get)
    SstiModule().scan("http://example.com/?name=hi", {})
    # 1 baseline (capture=False, implicite) + 4 sondes (capture=True, une par PROBES) = 5 appels
    assert mock_get.call_count == 5
    assert mock_get.call_args_list[0].kwargs.get("capture", False) is False


def test_ssti_skips_target_with_no_params():
    from scanner.modules.ssti import SstiModule
    assert SstiModule().scan("http://example.com/", {}) == []
