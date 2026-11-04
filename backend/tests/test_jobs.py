"""Tests du JobStore (scans en arrière-plan)."""
import threading
import pytest
from scanner.core.jobs import JobStore, TooManyJobs, MAX_RUNNING, RETENTION_S


def _wait_status(store, job_id, status, timeout=5):
    done = threading.Event()
    for _ in range(int(timeout * 100)):
        if store.snapshot(job_id)["status"] == status:
            return True
        done.wait(0.01)
    return False


def _blocking_run(gate, entered=None):
    def run(target, context, enabled, crawl):
        context["module_log"].append({"module": "m1", "findings": 0, "elapsed_ms": 1})
        if entered:
            entered.set()
        gate.wait(5)
        return ["F"]
    return run


def test_job_visible_mid_run():
    gate, entered = threading.Event(), threading.Event()
    store = JobStore()
    try:
        jid = store.create(_blocking_run(gate, entered), "http://t", {}, None, True)
        assert entered.wait(5)
        snap = store.snapshot(jid)
        assert snap["status"] == "running"
        assert [e["module"] for e in snap["module_log"]] == ["m1"]
        assert snap["findings"] is None and snap["context"] is None
    finally:
        gate.set()
    assert _wait_status(store, jid, "done")


def test_job_done_returns_findings_and_context():
    store = JobStore()
    jid = store.create(lambda t, c, e, k: ["F1"], "http://t", {"x": 1}, None, True)
    assert _wait_status(store, jid, "done")
    snap = store.snapshot(jid)
    assert snap["findings"] == ["F1"]
    assert snap["context"]["x"] == 1
    assert snap["error"] is None


def test_job_error_keeps_message():
    def boom(t, c, e, k):
        raise RuntimeError("kaboom")
    store = JobStore()
    jid = store.create(boom, "http://t", {}, None, True)
    assert _wait_status(store, jid, "error")
    assert "kaboom" in store.snapshot(jid)["error"]


def test_cancel_sets_deadline_and_flag_and_status():
    import time
    gate, entered = threading.Event(), threading.Event()
    seen = {}

    def run(t, ctx, e, k):
        entered.set()
        gate.wait(5)
        seen["cancelled"] = ctx.get("cancelled")
        seen["expired"] = ctx["deadline"] <= time.monotonic()
        return ["partial"]

    store = JobStore()
    try:
        jid = store.create(run, "http://t", {}, None, True)
        assert entered.wait(5)
        assert store.cancel(jid) is True
    finally:
        gate.set()
    assert _wait_status(store, jid, "cancelled")
    assert seen == {"cancelled": True, "expired": True}
    assert store.snapshot(jid)["findings"] == ["partial"]


def test_cancel_finished_job_is_noop():
    store = JobStore()
    jid = store.create(lambda t, c, e, k: [], "http://t", {}, None, True)
    assert _wait_status(store, jid, "done")
    assert store.cancel(jid) is True
    assert store.snapshot(jid)["status"] == "done"
    assert store.cancel("nope") is False


def test_third_concurrent_job_raises_too_many():
    gate = threading.Event()
    store = JobStore()
    ids = []
    try:
        for _ in range(MAX_RUNNING):
            ids.append(store.create(_blocking_run(gate), "http://t", {}, None, True))
        with pytest.raises(TooManyJobs):
            store.create(_blocking_run(gate), "http://t", {}, None, True)
    finally:
        gate.set()
    assert _wait_status(store, ids[0], "done")
    assert _wait_status(store, ids[1], "done")
    assert store.create(lambda t, c, e, k: [], "http://t", {}, None, True)


def test_finished_job_purged_after_retention():
    now = [1000.0]
    store = JobStore(clock=lambda: now[0])
    jid = store.create(lambda t, c, e, k: [], "http://t", {}, None, True)
    assert _wait_status(store, jid, "done")
    now[0] += RETENTION_S + 1
    assert store.snapshot(jid) is None


def test_unknown_job_snapshot_is_none():
    assert JobStore().snapshot("missing") is None


def test_systemexit_in_run_fn_ends_job_as_error_and_frees_slot():
    def die(t, c, e, k):
        raise SystemExit("bye")
    store = JobStore()
    ids = [store.create(die, "http://t", {}, None, True) for _ in range(MAX_RUNNING)]
    for jid in ids:
        assert _wait_status(store, jid, "error")
    assert store.create(lambda t, c, e, k: [], "http://t", {}, None, True)


def test_client_supplied_module_log_is_overwritten():
    gate, entered = threading.Event(), threading.Event()
    store = JobStore()
    try:
        jid = store.create(_blocking_run(gate, entered), "http://t", {"module_log": 5}, None, True)
        assert entered.wait(5)
        assert [e["module"] for e in store.snapshot(jid)["module_log"]] == ["m1"]
    finally:
        gate.set()
    assert _wait_status(store, jid, "done")


def test_thread_start_failure_frees_slot():
    from unittest.mock import patch
    store = JobStore()
    with patch("threading.Thread.start", side_effect=RuntimeError("no threads")):
        for _ in range(MAX_RUNNING + 1):
            with pytest.raises(RuntimeError):
                store.create(lambda t, c, e, k: [], "http://t", {}, None, True)
    assert store.create(lambda t, c, e, k: [], "http://t", {}, None, True)


def test_max_stored_drops_oldest_finished_never_running():
    import scanner.core.jobs as jobs
    now = [0.0]
    store = JobStore(clock=lambda: now[0])
    gate = threading.Event()
    try:
        running = store.create(_blocking_run(gate), "http://t", {}, None, True)
        finished = []
        for _ in range(jobs.MAX_STORED):
            now[0] += 1
            jid = store.create(lambda t, c, e, k: [], "http://t", {}, None, True)
            assert _wait_status(store, jid, "done")
            finished.append(jid)
        now[0] += 1
        store.create(lambda t, c, e, k: [], "http://t", {}, None, True)
        assert store.snapshot(running)["status"] == "running"
        assert store.snapshot(finished[0]) is None
        assert store.snapshot(finished[-1]) is not None
    finally:
        gate.set()


def test_cancel_finished_job_leaves_status_and_context_unchanged():
    store = JobStore()
    jid = store.create(lambda t, c, e, k: [], "http://t", {}, None, True)
    assert _wait_status(store, jid, "done")
    before = store.snapshot(jid)
    store.cancel(jid)
    after = store.snapshot(jid)
    assert after["status"] == "done"
    assert "cancelled" not in after["context"] and "deadline" not in after["context"]
    assert after["context"] == before["context"]


def test_finished_job_drops_auth_but_keeps_response_inputs():
    from routes.scanner_engine import _build_run_response
    ctx = {"auth": {"token": "secret"}, "depth": "basic"}

    def run(t, c, e, k):
        assert c["auth"]["token"] == "secret"  # disponible pendant le run
        c["module_log"].append({"module": "m1", "findings": 0, "elapsed_ms": 1})
        return []

    store = JobStore()
    jid = store.create(run, "http://t", ctx, None, True)
    assert _wait_status(store, jid, "done")
    snap = store.snapshot(jid)
    assert "auth" not in snap["context"]
    assert snap["context"]["depth"] == "basic"
    assert _build_run_response(snap["findings"], snap["context"])["moduleLog"][0]["module"] == "m1"
