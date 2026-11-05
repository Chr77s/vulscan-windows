"""Task 11 — Host-header / en-tête aveugle via rappel OOB."""


class HitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return [{"ts": 1, "method": "GET", "ip": "8.8.8.8", "user_agent": "proxy"}]


class NoHitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return []


def _run(mocker, channel):
    from scanner.modules.header_injection import HeaderInjectionModule
    resp = mocker.Mock(status_code=200, headers={}, text="", url="http://victim.test/")
    mocker.patch("scanner.core.http.get", return_value=resp)
    return HeaderInjectionModule().scan("http://victim.test/", {"oob_channel": channel})


def test_host_header_confirms_on_callback(mocker):
    findings = _run(mocker, HitChannel())
    oob = [f for f in findings if f.detection_method == "oob-canary"]
    assert oob and oob[0].confidence == 95


def test_host_header_no_hit_no_oob(mocker):
    findings = _run(mocker, NoHitChannel())
    assert [f for f in findings if f.detection_method == "oob-canary"] == []
