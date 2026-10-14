"""
conftest.py — fixtures pytest partagées.

Force sys.path à inclure le dossier parent (backend/) pour permettre les imports
`from scanner...` et `from database...`.
"""
import sys
import os

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)


def assert_module_propagates_auth(mocker, module_cls, target, extra_context=None):
    """Échoue si `module_cls` n'appelle pas scanner.core.http (donc ne propage pas context['auth'])."""
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mock_request = mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"headers": {"Authorization": "Bearer AUTH-PROPAGATION-TEST"}}}
    if extra_context:
        ctx.update(extra_context)
    module_cls().scan(target, ctx)
    assert mock_request.called, f"{module_cls.__name__} n'a fait aucun appel via scanner.core.http"
    assert any(
        call.kwargs.get("headers", {}).get("Authorization") == "Bearer AUTH-PROPAGATION-TEST"
        for call in mock_request.call_args_list
    ), f"{module_cls.__name__} ne propage pas context['auth'] — appel direct à requests toujours en place ?"
