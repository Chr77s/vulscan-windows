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
    assert data["discovery"]["forms"] == forms
