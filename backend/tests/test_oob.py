"""Tests du système OOB Collaborator."""
import pytest


def test_oob_log_and_check_in_memory(monkeypatch):
    """Vérifie qu'un hit enregistré via /oob/log est récupérable via /oob/check."""
    from scanner.core import oob_store

    oob_store._reset()
    oob_store.record_hit("test-uid-123", {
        "ts": 1700000000, "method": "GET", "ip": "1.2.3.4",
        "user_agent": "TestAgent", "headers": {}, "body": "", "query": {},
    })

    hits = oob_store.get_hits("test-uid-123")
    assert hits and hits[0]["method"] == "GET"


def test_oob_purge_old_entries(monkeypatch):
    """Les hits trop anciens doivent être purgés."""
    from scanner.core import oob_store
    import time

    oob_store._reset()
    oob_store.record_hit("old-uid", {"ts": time.time() - oob_store.TTL_SECONDS - 100, "method": "GET",
                                     "ip": "", "user_agent": "", "headers": {}, "body": "", "query": {}})
    oob_store.record_hit("new-uid", {"ts": time.time(), "method": "POST",
                                     "ip": "", "user_agent": "", "headers": {}, "body": "", "query": {}})
    oob_store.purge_old()
    assert oob_store.get_hits("old-uid") == []
    assert len(oob_store.get_hits("new-uid")) == 1


def test_oob_canary_helper_construct():
    """OOBCanary.new() doit retourner un objet utilisable même si backend HTTP est down."""
    from scanner.core.oob import OOBCanary
    # Le helper fallback localement si /oob/new n'est pas joignable
    canary = OOBCanary.new()
    assert canary.uid
    assert canary.url.startswith("http")
    assert canary.uid in canary.url
