"""Task 5 — listener canary isolé (scanner/core/oob_listener.py)."""
import requests

from scanner.core import oob_store
from scanner.core.oob_listener import start_listener


def test_log_path_records_hit():
    oob_store._reset()
    port, stop = start_listener(0)
    try:
        r = requests.get(f"http://127.0.0.1:{port}/oob/log/u1", timeout=3)
        assert r.status_code == 200
        hits = oob_store.get_hits("u1")
        assert len(hits) == 1 and hits[0]["method"] == "GET"
    finally:
        stop()


def test_non_log_path_404():
    port, stop = start_listener(0)
    try:
        for path in ("/scanner/run", "/history", "/oob/check/u1", "/"):
            r = requests.get(f"http://127.0.0.1:{port}{path}", timeout=3)
            assert r.status_code == 404, f"{path} devrait être 404 (isolation)"
    finally:
        stop()
