"""Task 12 — XSS stocké/aveugle via rappel OOB."""


class HitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return [{"ts": 1, "method": "GET", "ip": "2.2.2.2", "user_agent": "Mozilla"}]


class NoHitChannel:
    kind = "mock"

    def register(self, uid):
        return f"http://canary.example/oob/log/{uid}"

    def poll(self, uid):
        return []


def _run(mocker, channel):
    from scanner.modules.xss import XssModule

    resp = mocker.Mock(status_code=200, headers={}, text="")

    def fake_get(url, context, capture=False, **kw):
        return (resp, {"m": 1}, {"s": 1}) if capture else resp

    def fake_post(url, context, capture=False, **kw):
        return (resp, {"m": 1}, {"s": 1}) if capture else resp

    mocker.patch("scanner.core.http.get", side_effect=fake_get)
    mocker.patch("scanner.core.http.post", side_effect=fake_post)
    ctx = {
        "oob_channel": channel,
        "crawled": {
            "urls": ["http://victim.test/wall"],
            "forms": [{"action": "http://victim.test/comment", "method": "POST",
                       "fields": [{"name": "body", "type": "text"}]}],
        },
    }
    return XssModule().scan("http://victim.test/comment?text=hi", ctx)


def test_blind_xss_confirms_after_recrawl(mocker):
    findings = _run(mocker, HitChannel())
    oob = [f for f in findings if f.detection_method == "oob-canary"]
    assert oob and oob[0].type == "xss" and oob[0].confidence == 95


def test_blind_xss_no_hit_no_finding(mocker):
    findings = _run(mocker, NoHitChannel())
    assert [f for f in findings if f.detection_method == "oob-canary"] == []
