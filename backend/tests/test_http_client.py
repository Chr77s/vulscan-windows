"""Tests du helper HTTP avec injection d'auth."""
import pytest


def test_merged_kwargs_injects_cookies():
    from scanner.core.http import _merged_kwargs
    ctx = {"auth": {"cookies": {"sessionid": "abc"}}}
    out = _merged_kwargs(ctx, {})
    assert out["cookies"] == {"sessionid": "abc"}


def test_merged_kwargs_injects_auth_headers():
    from scanner.core.http import _merged_kwargs
    ctx = {"auth": {"headers": {"Authorization": "Bearer eyJ..."}}}
    out = _merged_kwargs(ctx, {})
    assert out["headers"]["Authorization"] == "Bearer eyJ..."


def test_merged_kwargs_default_user_agent():
    from scanner.core.http import _merged_kwargs, DEFAULT_UA
    out = _merged_kwargs(None, {})
    assert out["headers"]["User-Agent"] == DEFAULT_UA


def test_merged_kwargs_user_override_wins():
    """Si le caller passe un User-Agent explicite, il prime."""
    from scanner.core.http import _merged_kwargs
    out = _merged_kwargs(None, {"headers": {"User-Agent": "Custom"}})
    assert out["headers"]["User-Agent"] == "Custom"


def test_has_auth():
    from scanner.core.http import has_auth
    assert not has_auth(None)
    assert not has_auth({})
    assert not has_auth({"auth": {}})
    assert has_auth({"auth": {"cookies": {"a": "b"}}})
    assert has_auth({"auth": {"headers": {"X": "Y"}}})


def test_send_without_capture_returns_plain_response(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={"Server": "nginx"}, text="ok")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    result = http.send("GET", "http://example.com/x")
    assert result is fake

def test_send_with_capture_returns_triple(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={"Server": "nginx"}, text="ok")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    response, req_ev, resp_ev = http.send("GET", "http://example.com/x", capture=True)
    assert response is fake
    assert req_ev["method"] == "GET" and req_ev["url"] == "http://example.com/x"
    assert resp_ev["status"] == 200 and resp_ev["body_snippet"] == "ok"

def test_capture_redacts_authorization_header(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"headers": {"Authorization": "Bearer secret-token"}}}
    _, req_ev, _ = http.send("GET", "http://example.com/x", context=ctx, capture=True)
    assert req_ev["headers"]["Authorization"] == "***"

def test_capture_redacts_cookie_header_and_set_cookie_response_header(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={"Set-Cookie": "session=abc123"}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"cookies": {"session": "abc123"}}}
    _, req_ev, resp_ev = http.send("GET", "http://example.com/x", context=ctx, capture=True,
                                    headers={"Cookie": "session=abc123"})
    assert req_ev["headers"]["Cookie"] == "***"
    assert resp_ev["headers"]["Set-Cookie"] == "***"

def test_capture_omits_basic_auth_tuple_from_evidence(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"basic": ("admin", "s3cr3t")}}
    _, req_ev, _ = http.send("GET", "http://example.com/x", context=ctx, capture=True)
    assert "s3cr3t" not in str(req_ev)
    assert "auth" not in req_ev

def test_capture_truncates_body_snippet_to_4096_bytes(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="A" * 10000)
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    _, _, resp_ev = http.send("GET", "http://example.com/x", capture=True)
    assert len(resp_ev["body_snippet"]) == 4096

def test_send_capture_on_network_error_returns_none_triple(mocker):
    from scanner.core import http
    import requests as requests_module
    mocker.patch("scanner.core.http.requests.request", side_effect=requests_module.exceptions.ConnectionError())
    result = http.send("GET", "http://example.com/x", capture=True)
    assert result == (None, None, None)

def test_get_and_post_pass_capture_through(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="ok")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    response, req_ev, resp_ev = http.get("http://example.com/x", capture=True)
    assert response is fake and req_ev["method"] == "GET"
    response2, req_ev2, resp_ev2 = http.post("http://example.com/x", capture=True, json={"a": 1})
    assert response2 is fake and req_ev2["method"] == "POST"
