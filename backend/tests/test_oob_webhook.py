"""Task 3 — adaptateur webhook.site (scanner/core/oob_webhook.py)."""


def _raw(path, method="GET"):
    # Forme brute renvoyée par l'API webhook.site (champs réduits à l'utile).
    return {
        "method": method,
        "url": f"https://webhook.site/TOKEN{path}",
        "ip": "9.9.9.9",
        "headers": {"user-agent": ["curl/8"]},
        "content": "",
        "query": {},
        "created_at": "2026-11-05 10:00:00",
    }


def test_register_returns_url_with_uid():
    from scanner.core.oob_webhook import WebhookChannel
    ch = WebhookChannel(token="TOKEN", fetch_requests=lambda t: [])
    url = ch.register("abc123")
    assert "TOKEN" in url and "abc123" in url
    assert ch.kind == "webhook"


def test_poll_normalizes_and_filters_by_uid():
    from scanner.core.oob_webhook import WebhookChannel
    reqs = [_raw("/abc123", "GET"), _raw("/autre", "POST")]
    ch = WebhookChannel(token="TOKEN", fetch_requests=lambda t: reqs)
    hits = ch.poll("abc123")
    assert len(hits) == 1
    assert hits[0]["method"] == "GET"
    assert hits[0]["ip"] == "9.9.9.9"
    assert "ts" in hits[0]


def test_poll_returns_empty_on_api_error():
    from scanner.core.oob_webhook import WebhookChannel

    def boom(_t):
        raise RuntimeError("API down")

    ch = WebhookChannel(token="TOKEN", fetch_requests=boom)
    assert ch.poll("abc123") == []
