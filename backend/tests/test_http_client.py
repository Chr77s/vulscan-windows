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
