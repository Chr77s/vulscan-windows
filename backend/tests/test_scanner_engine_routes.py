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


# ---- Jobs (scan en arrière-plan) -------------------------------------------

def _wait_for(pred, timeout=5.0):
    import time
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.01)
    return False


def _jobs_client(mocker, run_side_effect):
    """Client Flask + JobStore neuf (les tests ne partagent pas d'état)."""
    import routes.scanner_engine as se
    from scanner.core.jobs import JobStore
    mocker.patch.object(se, "_jobs", JobStore())
    return _client_with_engine(mocker, run_side_effect)


def _gated_run(release, seen=None, findings=None):
    """run() qui attend `release` ; relâché dans finally par le test."""
    def run(target, context=None, enabled=None, crawl=True):
        if seen is not None:
            seen.update(context)
        release.wait(5)
        context["module_log"].append({"module": "headers", "findings": 0, "elapsed_ms": 4})
        return findings or []
    return run


def test_run_response_builder_matches_run_endpoint(mocker):
    from routes.scanner_engine import _build_run_response

    def run_side_effect(target, context=None, enabled=None, crawl=True):
        context["module_log"] = [{"module": "a", "findings": 0, "elapsed_ms": 1}]
        context["crawled"] = {"urls": [target], "forms": [], "api_endpoints": [], "stats": {"n": 1}}
        return []

    client, _ = _client_with_engine(mocker, run_side_effect)
    body = client.post("/scanner/run", json={"target": "http://x/"}).get_json()
    ctx = {"module_log": [{"module": "a", "findings": 0, "elapsed_ms": 1}],
           "crawled": {"urls": ["http://x/"], "forms": [], "api_endpoints": [], "stats": {"n": 1}}}
    assert _build_run_response([], ctx) == body


def test_run_with_null_context_is_not_500(mocker):
    seen = {}

    def run_side_effect(target, context=None, enabled=None, crawl=True):
        seen["ctx"] = context
        return []

    client, _ = _client_with_engine(mocker, run_side_effect)
    resp = client.post("/scanner/run", json={"target": "http://x/", "context": None})
    assert resp.status_code == 200
    assert isinstance(seen["ctx"], dict)


def test_jobs_post_returns_202_and_id(mocker):
    import threading
    release = threading.Event()
    client, _ = _jobs_client(mocker, _gated_run(release))
    try:
        resp = client.post("/scanner/jobs", json={"target": "http://x/"})
        assert resp.status_code == 202
        assert resp.get_json()["jobId"]
    finally:
        release.set()


def test_jobs_post_without_target_400(mocker):
    client, _ = _jobs_client(mocker, lambda *a, **k: [])
    assert client.post("/scanner/jobs", json={}).status_code == 400


def test_jobs_post_429_when_too_many(mocker):
    import threading
    release = threading.Event()
    client, engine = _jobs_client(mocker, _gated_run(release))
    try:
        for _ in range(2):
            assert client.post("/scanner/jobs", json={"target": "http://x/"}).status_code == 202
        assert _wait_for(lambda: engine.run.call_count == 2)
        assert client.post("/scanner/jobs", json={"target": "http://x/"}).status_code == 429
        assert engine.run.call_count == 2
    finally:
        release.set()
    # un job fini libère une place
    def accepted():
        return client.post("/scanner/jobs", json={"target": "http://x/"}).status_code == 202
    assert _wait_for(accepted)


def test_jobs_get_running_then_done_with_result(mocker):
    import threading
    from routes.scanner_engine import _build_run_response
    release = threading.Event()
    seen = {}
    client, engine = _jobs_client(mocker, _gated_run(release, seen))
    try:
        jid = client.post("/scanner/jobs", json={"target": "http://x/"}).get_json()["jobId"]
        assert _wait_for(lambda: engine.run.call_count == 1)
        body = client.get(f"/scanner/jobs/{jid}").get_json()
        assert body["status"] == "running"
        assert body["jobId"] == jid
        assert body["moduleLog"] == []
        assert "result" not in body
    finally:
        release.set()
    assert _wait_for(lambda: client.get(f"/scanner/jobs/{jid}").get_json()["status"] == "done")
    body = client.get(f"/scanner/jobs/{jid}").get_json()
    log = [{"module": "headers", "findings": 0, "elapsed_ms": 4}]
    assert body["moduleLog"] == [{"module": "headers", "findings": 0, "elapsedMs": 4}]
    assert body["result"] == _build_run_response([], {"module_log": log})
    assert "elapsedMs" in body and "currentModule" in body


def test_jobs_get_unknown_404(mocker):
    client, _ = _jobs_client(mocker, lambda *a, **k: [])
    assert client.get("/scanner/jobs/nope").status_code == 404


def test_jobs_delete_202_and_unknown_404(mocker):
    import threading
    release = threading.Event()
    client, engine = _jobs_client(mocker, _gated_run(release))
    try:
        jid = client.post("/scanner/jobs", json={"target": "http://x/"}).get_json()["jobId"]
        resp = client.delete(f"/scanner/jobs/{jid}")
        assert resp.status_code == 202
        assert resp.get_json() == {"jobId": jid, "status": "cancelling"}
    finally:
        release.set()
    assert _wait_for(lambda: client.get(f"/scanner/jobs/{jid}").get_json()["status"] == "cancelled")
    assert client.delete("/scanner/jobs/nope").status_code == 404


def test_jobs_drop_client_control_keys(mocker):
    import threading
    release = threading.Event()
    seen = {}
    client, engine = _jobs_client(mocker, _gated_run(release, seen))
    try:
        resp = client.post("/scanner/jobs", json={"target": "http://x/", "context": {
            "deadline": 1, "cancelled": True, "current_module": "evil",
            "module_log": [{"x": 1}], "time_budget_s": 30}})
        assert resp.status_code == 202
        assert _wait_for(lambda: engine.run.call_count == 1)
    finally:
        release.set()
    for k in ("deadline", "cancelled", "current_module"):
        assert k not in seen
    assert seen["module_log"] == []
    assert seen["time_budget_s"] == 30


def test_jobs_post_non_dict_context_is_ok(mocker):
    client, _ = _jobs_client(mocker, lambda *a, **k: [])
    assert client.post("/scanner/jobs", json={"target": "http://x/", "context": "x"}).status_code == 202
