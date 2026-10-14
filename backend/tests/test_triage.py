import pytest


def test_init_db_migration_adds_triage_columns_idempotently(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    dbmod.init_db()  # doit être idempotent, pas d'exception "duplicate column"
    with dbmod._connect() as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    assert "triage_status" in cols and "triage_note" in cols


def test_set_triage_updates_existing_finding(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    dbmod.save_scan({"id": "s1", "url": "http://h.test", "startedAt": 1,
                      "vulnerabilities": [{"id": "v1", "type": "xss", "severity": "high", "url": "u"}]})
    assert dbmod.set_triage("v1", "confirmed", "vérifié manuellement") is True
    with dbmod._connect() as conn:
        row = conn.execute("SELECT triage_status, triage_note FROM findings WHERE id = 'v1'").fetchone()
    assert row["triage_status"] == "confirmed"
    assert row["triage_note"] == "vérifié manuellement"


def test_set_triage_returns_false_for_unknown_id(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    assert dbmod.set_triage("does-not-exist", "confirmed") is False


def test_set_triage_rejects_invalid_status(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    with pytest.raises(ValueError):
        dbmod.set_triage("v1", "maybe")


def test_set_triage_rejects_non_string_status(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    with pytest.raises(ValueError):
        dbmod.set_triage("v1", ["confirmed"])


def test_triage_endpoint_confirms_and_404s_on_unknown_id(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    dbmod.save_scan({"id": "s1", "url": "http://h.test", "startedAt": 1,
                      "vulnerabilities": [{"id": "v1", "type": "xss", "severity": "high", "url": "u"}]})

    from flask import Flask
    from routes.history import history_bp
    app = Flask(__name__)
    app.register_blueprint(history_bp)
    client = app.test_client()

    ok = client.patch("/triage/v1", json={"status": "false_positive", "note": "page générique"})
    assert ok.status_code == 200 and ok.get_json()["success"] is True

    missing = client.patch("/triage/unknown-id", json={"status": "confirmed"})
    assert missing.status_code == 404

    bad = client.patch("/triage/v1", json={"status": "bogus"})
    assert bad.status_code == 400
