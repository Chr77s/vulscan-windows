"""Task 8 — SSRF via le canal OOB du context."""


class HitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return [{"ts": 1, "method": "GET", "ip": "1.2.3.4", "user_agent": "curl"}]


class NoHitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return []


def _run(mocker, channel):
    from scanner.modules.ssrf import SsrfModule
    resp = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.get", return_value=resp)
    return SsrfModule().scan("http://victim.test/fetch?url=http://a.example",
                             {"oob_channel": channel})


def test_ssrf_confirms_on_canary_hit_via_context(mocker):
    findings = _run(mocker, HitChannel())
    oob = [f for f in findings if f.detection_method == "oob-canary"]
    assert oob and oob[0].type == "ssrf"


def test_ssrf_no_hit_no_oob_finding(mocker):
    findings = _run(mocker, NoHitChannel())
    assert [f for f in findings if f.detection_method == "oob-canary"] == []
