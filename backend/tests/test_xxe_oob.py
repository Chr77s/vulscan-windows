"""Task 9 — XXE blind via rappel OOB."""


class HitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return [{"ts": 1, "method": "GET", "ip": "5.5.5.5", "user_agent": "libxml"}]


class NoHitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return []


def _run(mocker, channel):
    from scanner.modules.xxe import XxeModule
    resp = mocker.Mock(status_code=200, headers={}, text="ok")
    mocker.patch("scanner.core.http.post", return_value=(resp, {"m": 1}, {"s": 1}))
    return XxeModule().scan("http://victim.test/api/xml", {"oob_channel": channel})


def test_xxe_confirms_on_entity_callback(mocker):
    findings = _run(mocker, HitChannel())
    oob = [f for f in findings if f.detection_method == "oob-canary"]
    assert oob and oob[0].type == "xxe" and oob[0].confidence == 95


def test_xxe_no_hit_no_oob_finding(mocker):
    findings = _run(mocker, NoHitChannel())
    assert [f for f in findings if f.detection_method == "oob-canary"] == []
