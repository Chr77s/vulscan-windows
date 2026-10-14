import time
from database.db import init_db, save_scan, risk_trend

def test_risk_trend_returns_chronological_scores_for_url(tmp_path, monkeypatch):
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test.db"))
    init_db()

    base = int(time.time() * 1000)
    for i, score in enumerate([10, 25, 5]):
        save_scan({
            "id": f"scan-{i}", "url": "http://example.com/",
            "startedAt": base + i * 1000, "finishedAt": base + i * 1000,
            "vulnerabilities": [{"severity": "critical"}] * (score // 10) + [{"severity": "low"}] * (score % 10),
        })

    trend = risk_trend("http://example.com/", limit=10)
    assert [t["started_at"] for t in trend] == [base, base + 1000, base + 2000]
    assert len(trend) == 3


def test_risk_trend_empty_for_unknown_url(tmp_path, monkeypatch):
    import database.db as db_module
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test2.db"))
    init_db()
    assert risk_trend("http://never-scanned.example/", limit=10) == []


def test_risk_trend_reflects_triage_not_the_frozen_save_time_score(tmp_path, monkeypatch):
    """Round 7 follow-up (M1) : le score stocké sur `scans` au save_scan() ne
    bouge jamais quand un finding est triagé plus tard -- risk_trend() doit
    donc recalculer le score en direct via les triage_status courants, pas
    lire la colonne figée."""
    import database.db as db_module
    from database.db import set_triage
    monkeypatch.setattr(db_module, "DB_PATH", str(tmp_path / "test3.db"))
    init_db()

    save_scan({
        "id": "scan-triaged", "url": "http://trend.test/",
        "startedAt": 1000, "finishedAt": 1000,
        "vulnerabilities": [
            {"id": "t1", "type": "sqli", "severity": "critical", "url": "u"},
            {"id": "t2", "type": "xss", "severity": "low", "url": "u"},
        ],
    })

    before = risk_trend("http://trend.test/", limit=10)
    assert before[0]["score"] == 11  # 1 critical (10) + 1 low (1)

    assert set_triage("t1", "false_positive") is True

    after = risk_trend("http://trend.test/", limit=10)
    assert after[0]["score"] == 1  # the critical no longer counts
