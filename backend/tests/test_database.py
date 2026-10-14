"""Tests de la couche SQLite (database.db)."""
import pytest
import os
import tempfile


def test_save_and_get_scan(monkeypatch, tmp_path):
    # Rediriger la DB vers un fichier temp
    db_file = tmp_path / "test.db"
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(db_file))
    dbmod.init_db()

    scan = {
        "id": "scan-test-1",
        "url": "http://test.local/page",
        "startedAt": 1700000000000,
        "finishedAt": 1700000005000,
        "vulnerabilities": [
            {"id": "v1", "type": "xss",  "severity": "high",     "confidence": 90,
             "title": "XSS", "url": "http://test.local/page", "parameter": "q"},
            {"id": "v2", "type": "sqli", "severity": "critical", "confidence": 95,
             "title": "SQLi", "url": "http://test.local/page", "parameter": "id"},
        ],
    }
    dbmod.save_scan(scan)

    fetched = dbmod.get_scan("scan-test-1")
    assert fetched is not None
    assert fetched["url"] == "http://test.local/page"
    assert len(fetched["vulnerabilities"]) == 2


def test_list_scans(monkeypatch, tmp_path):
    db_file = tmp_path / "test.db"
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(db_file))
    dbmod.init_db()

    for i in range(3):
        dbmod.save_scan({
            "id": f"scan-{i}", "url": f"http://h{i}.test",
            "startedAt": 1700000000000 + i * 1000,
            "vulnerabilities": [],
        })
    scans = dbmod.list_scans()
    assert len(scans) == 3
    # Tri DESC sur started_at
    assert scans[0]["id"] == "scan-2"


def test_diff_scans(monkeypatch, tmp_path):
    db_file = tmp_path / "test.db"
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(db_file))
    dbmod.init_db()

    dbmod.save_scan({"id": "a", "url": "http://h.test", "startedAt": 1, "vulnerabilities": [
        {"id": "v1", "type": "xss", "severity": "high", "url": "u", "parameter": "p1"},
        {"id": "v2", "type": "sqli", "severity": "critical", "url": "u", "parameter": "id"},
    ]})
    dbmod.save_scan({"id": "b", "url": "http://h.test", "startedAt": 2, "vulnerabilities": [
        {"id": "v1b", "type": "xss", "severity": "high", "url": "u", "parameter": "p1"},  # stable
        {"id": "v3",  "type": "csrf", "severity": "medium", "url": "u", "parameter": "form"},  # added
        # v2 (sqli) supprimé
    ]})

    diff = dbmod.diff_scans("a", "b")
    assert len(diff["added"]) == 1
    assert len(diff["removed"]) == 1
    assert diff["stable_count"] == 1
