def test_run_scan_discovery_includes_full_form_list(mocker):
    from flask import Flask
    from routes.scanner_engine import scanner_bp

    app = Flask(__name__)
    app.register_blueprint(scanner_bp, url_prefix="/scanner")
    client = app.test_client()

    fake_engine = mocker.Mock()
    fake_engine.run.return_value = []
    fake_engine.list_modules.return_value = [{"name": "headers", "default_enabled": True}]
    fake_engine.last_module_log = []
    mocker.patch("routes.scanner_engine.get_engine", return_value=fake_engine)

    forms = [{"action": "http://x/login", "method": "POST",
              "fields": [{"name": "user", "type": "text", "value": "", "required": True}],
              "id": "login-form"}]

    def run_side_effect(target, context=None, enabled=None, crawl=True):
        context["crawled"] = {"urls": [target], "forms": forms, "api_endpoints": [], "stats": {}}
        return []
    fake_engine.run.side_effect = run_side_effect

    resp = client.post("/scanner/run", json={"target": "http://x/"})
    data = resp.get_json()
    returned_forms = data["discovery"]["forms"]
    assert len(returned_forms) == 1
    returned_form = returned_forms[0]
    # action/method/id must survive untouched
    assert returned_form["action"] == "http://x/login"
    assert returned_form["method"] == "POST"
    assert returned_form["id"] == "login-form"
    # Fix 6 (final-fix-wave) : field.value must NOT appear in the response —
    # the Surface tab never renders it, so it should never leave the backend.
    returned_fields = returned_form["fields"]
    assert returned_fields == [{"name": "user", "type": "text", "required": True}]
    assert "value" not in returned_fields[0]


def _client_with_engine(mocker, run_side_effect):
    from flask import Flask
    from routes.scanner_engine import scanner_bp

    app = Flask(__name__)
    app.register_blueprint(scanner_bp, url_prefix="/scanner")
    fake_engine = mocker.Mock()
    fake_engine.list_modules.return_value = [{"name": "headers", "default_enabled": True}]
    fake_engine.run.side_effect = run_side_effect
    mocker.patch("routes.scanner_engine.get_engine", return_value=fake_engine)
    return app.test_client(), fake_engine


def test_run_scan_drops_client_supplied_deadline(mocker):
    seen = {}

    def run_side_effect(target, context=None, enabled=None, crawl=True):
        seen.update(context)
        return []

    client, _ = _client_with_engine(mocker, run_side_effect)
    resp = client.post("/scanner/run", json={
        "target": "http://x/", "context": {"deadline": "soon", "time_budget_s": 30}})
    assert resp.status_code == 200
    assert "deadline" not in seen
    assert seen["time_budget_s"] == 30


def test_run_scan_modules_run_excludes_skipped(mocker):
    def run_side_effect(target, context=None, enabled=None, crawl=True):
        context["module_log"] = [
            {"module": "a", "findings": 1, "elapsed_ms": 5},
            {"module": "b", "findings": 0, "elapsed_ms": 3, "status": "error", "error": "boom"},
            {"module": "c", "findings": 0, "elapsed_ms": 0, "status": "skipped", "reason": "time_budget"},
        ]
        return []

    client, _ = _client_with_engine(mocker, run_side_effect)
    resp = client.post("/scanner/run", json={"target": "http://x/", "enabled": ["a", "b", "c"]})
    assert resp.get_json()["stats"]["modules_run"] == 2


def test_module_log_entry_exposes_skipped():
    from routes.scanner_engine import _module_log_entry
    raw = {"module": "x", "findings": 0, "elapsed_ms": 0,
           "status": "skipped", "reason": "time_budget"}
    assert _module_log_entry(raw) == {"module": "x", "findings": 0, "elapsedMs": 0,
                                      "status": "skipped", "reason": "time_budget"}
