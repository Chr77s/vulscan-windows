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


def test_throttle_does_not_hold_the_lock_while_sleeping(mocker):
    """Pendant qu'un thread dort pour l'hôte A, une requête vers l'hôte B ne doit pas attendre."""
    import threading
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    mocker.patch("scanner.core.http.time.monotonic", return_value=100.0)
    a_sleeping, release_a = threading.Event(), threading.Event()

    def fake_sleep(seconds):
        a_sleeping.set()
        release_a.wait(5)

    mocker.patch("scanner.core.http.time.sleep", side_effect=fake_sleep)
    ctx = {"rate_limit_per_sec": 10}
    http.send("GET", "http://a.test/one", context=ctx)  # pas d'attente : premier appel
    t = threading.Thread(target=http.send, args=("GET", "http://a.test/two"), kwargs={"context": ctx})
    t.start()
    try:
        assert a_sleeping.wait(5)
        b_done = threading.Event()
        threading.Thread(target=lambda: (http.send("GET", "http://b.test/one", context=ctx),
                                         b_done.set()), daemon=True).start()
        assert b_done.wait(2), "la requête vers B a attendu le sommeil de A"
    finally:
        release_a.set()
        t.join(5)


def test_throttle_reserves_successive_slots_for_one_host(mocker):
    """Deux attentes concurrentes pour le même hôte réservent des créneaux distincts."""
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    sleep_mock = mocker.patch("scanner.core.http.time.sleep")
    mocker.patch("scanner.core.http.time.monotonic", return_value=100.0)
    for _ in range(3):
        http.send("GET", "http://d.test/x", context={"rate_limit_per_sec": 10})
    waits = [c.args[0] for c in sleep_mock.call_args_list]
    assert len(waits) == 2
    assert abs(waits[0] - 0.1) < 1e-9 and abs(waits[1] - 0.2) < 1e-9


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
