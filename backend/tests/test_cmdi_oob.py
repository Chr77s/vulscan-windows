"""Task 10 — command injection aveugle via rappel OOB."""


class HitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return [{"ts": 1, "method": "GET", "ip": "7.7.7.7", "user_agent": "curl"}]


class NoHitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return []


def _run(mocker, channel):
    from scanner.modules.command_injection import CommandInjectionModule
    resp = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.get", return_value=(resp, {"m": 1}, {"s": 1}))
    return CommandInjectionModule().scan("http://victim.test/run?cmd=ls",
                                         {"oob_channel": channel})


def test_cmdi_confirms_on_curl_callback(mocker):
    findings = _run(mocker, HitChannel())
    oob = [f for f in findings if f.detection_method == "oob-canary"]
    assert oob and oob[0].type == "command-injection" and oob[0].confidence == 95


def test_cmdi_no_hit_no_oob_finding(mocker):
    findings = _run(mocker, NoHitChannel())
    assert [f for f in findings if f.detection_method == "oob-canary"] == []
