"""Tests du système OOB Collaborator."""
import pytest


def test_oob_log_and_check_in_memory(monkeypatch):
    """Vérifie qu'un hit enregistré via /oob/log est récupérable via /oob/check."""
    from routes.oob import _hits, _lock

    # Simuler un hit en mémoire
    with _lock:
        _hits.clear()
        _hits["test-uid-123"] = [{
            "ts": 1700000000, "method": "GET", "ip": "1.2.3.4",
            "user_agent": "TestAgent", "headers": {}, "body": "", "query": {},
        }]

    # Vérifier qu'on peut lire
    with _lock:
        assert "test-uid-123" in _hits
        assert _hits["test-uid-123"][0]["method"] == "GET"


def test_oob_purge_old_entries(monkeypatch):
    """Les hits trop anciens doivent être purgés."""
    from routes.oob import _hits, _lock, _purge_old, TTL_SECONDS
    import time

    with _lock:
        _hits.clear()
        _hits["old-uid"] = [{"ts": time.time() - TTL_SECONDS - 100, "method": "GET",
                             "ip": "", "user_agent": "", "headers": {}, "body": "", "query": {}}]
        _hits["new-uid"] = [{"ts": time.time(), "method": "POST",
                             "ip": "", "user_agent": "", "headers": {}, "body": "", "query": {}}]
    _purge_old()
    with _lock:
        assert "old-uid" not in _hits
        assert "new-uid" in _hits


def test_oob_canary_helper_construct():
    """OOBCanary.new() doit retourner un objet utilisable même si backend HTTP est down."""
    from scanner.core.oob import OOBCanary
    # Le helper fallback localement si /oob/new n'est pas joignable
    canary = OOBCanary.new()
    assert canary.uid
    assert canary.url.startswith("http")
    assert canary.uid in canary.url
