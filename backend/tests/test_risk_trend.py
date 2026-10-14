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
