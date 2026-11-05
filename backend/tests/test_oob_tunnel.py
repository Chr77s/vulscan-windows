"""Task 4 — gestionnaire de tunnel (scanner/core/oob_tunnel.py)."""


class FakeProc:
    def __init__(self, lines):
        self._lines = list(lines)
        self.terminated = False

        class _Out:
            def __init__(self, outer):
                self._outer = outer

            def readline(self):
                return self._outer._lines.pop(0) if self._outer._lines else ""

        self.stdout = _Out(self)

    def terminate(self):
        self.terminated = True

    def poll(self):
        return None


def test_parse_cloudflared_url_from_stdout():
    from scanner.core.oob_tunnel import start_tunnel
    proc = FakeProc([
        "2026-11-05 INF Starting tunnel\n",
        "2026-11-05 INF https://glad-brave-foo.trycloudflare.com\n",
    ])
    res = start_tunnel(9877, spawn=lambda args: proc, detect=lambda: "cloudflared", timeout_s=5)
    assert res is not None
    url, stop = res
    assert url == "https://glad-brave-foo.trycloudflare.com"
    stop()
    assert proc.terminated is True


def test_returns_none_when_no_binary():
    from scanner.core.oob_tunnel import start_tunnel
    assert start_tunnel(9877, spawn=lambda args: None, detect=lambda: None) is None


def test_returns_none_on_timeout():
    from scanner.core.oob_tunnel import start_tunnel
    proc = FakeProc(["noise\n", "noise\n", "noise\n", "noise\n"])
    t = {"n": 0}

    def clock():
        t["n"] += 10
        return t["n"]

    res = start_tunnel(9877, spawn=lambda args: proc, detect=lambda: "cloudflared",
                       timeout_s=5, clock=clock)
    assert res is None
    assert proc.terminated is True
