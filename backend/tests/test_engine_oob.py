"""Task 7 — câblage OOB dans l'engine (sélection de canal + teardown)."""


class SpyChannel:
    kind = "tunnel"

    def __init__(self):
        self.stopped = False

    def register(self, uid):
        return f"http://spy/oob/log/{uid}"

    def poll(self, uid):
        return []

    def stop(self):
        self.stopped = True


def test_run_sets_oob_channel_in_context():
    from scanner.core.engine import ScannerEngine
    eng = ScannerEngine()
    ctx = {}
    eng.run("http://localhost:9876/x", context=ctx, enabled=[], crawl=False)
    assert ctx.get("oob_channel") is not None
    assert ctx["oob_channel"].kind == "local"


def test_run_tears_down_channel(monkeypatch):
    from scanner.core.engine import ScannerEngine
    spy = SpyChannel()
    monkeypatch.setattr("scanner.core.oob_channel.select_channel", lambda *a, **k: spy)
    eng = ScannerEngine()
    eng.run("https://ginandjuice.shop/x", context={}, enabled=[], crawl=False)
    assert spy.stopped is True
