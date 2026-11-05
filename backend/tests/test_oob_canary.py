"""Task 6 — OOBCanary unifié sur canaux (scanner/core/oob.py)."""
import time


class MockChannel:
    kind = "mock"

    def __init__(self):
        self.store = {}

    def register(self, uid):
        return f"http://mock/oob/log/{uid}"

    def poll(self, uid):
        return self.store.get(uid, [])


def test_hit_on_matching_uid_confirms():
    from scanner.core.oob import OOBCanary
    ch = MockChannel()
    c = OOBCanary.new({"oob_channel": ch})
    ch.store[c.uid] = [{"ts": time.time(), "method": "GET"}]
    assert c.was_hit() is True
    assert c.hit_count() == 1


def test_hit_on_other_uid_does_not_confirm():
    from scanner.core.oob import OOBCanary
    ch = MockChannel()
    c = OOBCanary.new({"oob_channel": ch})
    ch.store["un-autre-uid"] = [{"ts": time.time(), "method": "GET"}]
    assert c.was_hit() is False


def test_new_without_context_uses_local():
    from scanner.core.oob import OOBCanary
    c = OOBCanary.new()
    assert c.uid
    assert c.url and c.uid in c.url


def test_wait_for_hit_bounded_by_deadline():
    from scanner.core.oob import OOBCanary
    ch = MockChannel()
    c = OOBCanary.new({"oob_channel": ch})
    ctx = {"oob_channel": ch, "deadline": time.monotonic() + 0.2}
    t0 = time.time()
    assert c.wait_for_hit(ctx, timeout=5, poll=0.05) is False
    assert time.time() - t0 < 2, "wait_for_hit doit respecter la deadline, pas dormir 5s"
