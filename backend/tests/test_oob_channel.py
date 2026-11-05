"""Task 2 — sélecteur de canal OOB (scanner/core/oob_channel.py)."""


def test_is_local_target():
    from scanner.core.oob_channel import is_local_target
    assert is_local_target("http://localhost:8080/x")
    assert is_local_target("http://127.0.0.1/x")
    assert is_local_target("http://app.test/x")
    assert is_local_target("http://foo.localhost/x")
    assert not is_local_target("https://ginandjuice.shop/catalog")


def test_select_local_for_local_target():
    from scanner.core.oob_channel import select_channel
    ch = select_channel("http://localhost:9876/x", mode="auto")
    assert ch.kind == "local"
    assert ch.register("u1").endswith("/oob/log/u1")


def test_select_off_disables():
    from scanner.core.oob_channel import select_channel
    ch = select_channel("https://ginandjuice.shop/x", mode="off")
    assert ch.register("u1") is None


def test_select_forces_explicit_webhook():
    from scanner.core.oob_channel import select_channel
    sentinel = object()
    called = {}

    def make_webhook():
        called["webhook"] = True
        return sentinel

    ch = select_channel("https://ginandjuice.shop/x", mode="webhook",
                        make_webhook=make_webhook)
    assert called.get("webhook") is True
    assert ch is sentinel


def test_select_auto_public_tunnel_then_webhook():
    from scanner.core.oob_channel import select_channel
    order = []

    def make_tunnel():
        order.append("tunnel")
        return None  # pas de binaire -> passe au suivant

    sentinel = object()

    def make_webhook():
        order.append("webhook")
        return sentinel

    ch = select_channel("https://ginandjuice.shop/x", mode="auto",
                        make_tunnel=make_tunnel, make_webhook=make_webhook)
    assert order == ["tunnel", "webhook"]
    assert ch is sentinel
