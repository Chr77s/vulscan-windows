"""Task 1 — magasin de hits OOB partagé (scanner/core/oob_store.py)."""
import time


def test_record_then_get_returns_hit():
    from scanner.core import oob_store
    oob_store._reset()
    oob_store.record_hit("u1", {"ts": time.time(), "method": "GET"})
    hits = oob_store.get_hits("u1")
    assert len(hits) == 1
    assert hits[0]["method"] == "GET"


def test_purge_drops_entries_older_than_ttl():
    from scanner.core import oob_store
    oob_store._reset()
    oob_store.record_hit("old", {"ts": time.time() - 700, "method": "GET"})
    oob_store.record_hit("fresh", {"ts": time.time(), "method": "GET"})
    oob_store.purge_old(600)
    assert oob_store.get_hits("old") == []
    assert len(oob_store.get_hits("fresh")) == 1


def test_get_unknown_uid_returns_empty():
    from scanner.core import oob_store
    oob_store._reset()
    assert oob_store.get_hits("inconnu") == []
