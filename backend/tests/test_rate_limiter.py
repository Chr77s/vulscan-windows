import time


def test_throttle_waits_between_calls_to_same_host(mocker):
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    sleep_mock = mocker.patch("scanner.core.http.time.sleep")
    # `send()` also reads time.monotonic() internally for its own elapsed_ms timing, so this
    # test does not try to count exact calls — it uses a shared mutable clock that always
    # returns the current instant, and advances it by exactly 0.02s between the two send()s.
    clock = {"t": 100.0}
    mocker.patch("scanner.core.http.time.monotonic", side_effect=lambda: clock["t"])

    http.send("GET", "http://a.test/one", context={"rate_limit_per_sec": 10})
    clock["t"] += 0.02  # only 20ms later — below the 100ms floor for 10 req/s
    http.send("GET", "http://a.test/two", context={"rate_limit_per_sec": 10})

    sleep_mock.assert_called_once()
    waited = sleep_mock.call_args[0][0]
    assert 0.07 < waited < 0.09  # ~0.1s floor minus the 0.02s already elapsed


def test_throttle_does_not_wait_for_different_hosts(mocker):
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    sleep_mock = mocker.patch("scanner.core.http.time.sleep")
    mocker.patch("scanner.core.http.time.monotonic", return_value=100.0)

    http.send("GET", "http://a.test/one", context={"rate_limit_per_sec": 10})
    http.send("GET", "http://b.test/one", context={"rate_limit_per_sec": 10})

    sleep_mock.assert_not_called()


def test_throttle_defaults_to_10_per_second_when_unconfigured(mocker):
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    sleep_mock = mocker.patch("scanner.core.http.time.sleep")
    # A constant clock (not a fixed-length iterator): `send()` now calls time.monotonic()
    # for both throttling and its own elapsed_ms evidence timing, so a 4-value iterator
    # would run out partway through the second call. Returning a fixed instant sidesteps
    # counting exact call counts while still exercising the "called twice at the same
    # instant" throttling path.
    mocker.patch("scanner.core.http.time.monotonic", return_value=100.0)

    http.send("GET", "http://c.test/one", context=None)
    http.send("GET", "http://c.test/two", context=None)

    sleep_mock.assert_called_once()
