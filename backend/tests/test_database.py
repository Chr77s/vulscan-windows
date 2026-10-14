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


def test_list_scans_excludes_false_positives_from_live_counts(monkeypatch, tmp_path):
    """Round 7 follow-up (M1) : set_triage() ne touche que la table `findings`,
    jamais les colonnes critical/high/.../score/total figées sur `scans` au
    moment du save_scan(). list_scans() doit donc recalculer ces chiffres en
    direct (LEFT JOIN sur findings, en excluant triage_status='false_positive'),
    pas renvoyer les valeurs figées."""
    db_file = tmp_path / "test.db"
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(db_file))
    dbmod.init_db()

    dbmod.save_scan({
        "id": "scan-fp", "url": "http://fp.test", "startedAt": 1,
        "vulnerabilities": [
            {"id": "f1", "type": "sqli", "severity": "critical", "url": "u"},
            {"id": "f2", "type": "xss",  "severity": "critical", "url": "u"},
            {"id": "f3", "type": "weak-csp", "severity": "medium", "url": "u"},
        ],
    })

    before = dbmod.list_scans()[0]
    assert before["critical"] == 2
    assert before["total"] == 3

    assert dbmod.set_triage("f1", "false_positive") is True

    after = dbmod.list_scans()[0]
    assert after["critical"] == 1   # f1 excluded, f2 still counted
    assert after["medium"] == 1
    assert after["total"] == 2
    assert after["score"] < before["score"]

    # The stored JSON payload (get_scan) is NOT touched by this fix -- it
    # stays a frozen snapshot of what was originally saved, by design.
    stale_payload = dbmod.get_scan("scan-fp")
    assert len(stale_payload["vulnerabilities"]) == 3


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
