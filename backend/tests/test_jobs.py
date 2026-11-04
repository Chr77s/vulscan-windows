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
