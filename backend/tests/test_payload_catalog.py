# backend/tests/test_payload_catalog.py
import pytest


@pytest.fixture
def mock_family(monkeypatch):
    """Isole un faux catalogue en mémoire — n'affecte pas les vrais fichiers JSON."""
    from scanner.payloads import catalog
    data = {
        "family": "testfam", "version": "1.0.0",
        "categories": {
            "cat_a": [
                {"payload": "p1"},                               # pas de depth -> basic
                {"payload": "p2", "depth": "extended"},
                {"payload": "p3", "depth": "aggressive"},
            ],
        },
    }
    monkeypatch.setitem(catalog._cache, "testfam", data)
    return catalog


def test_depth_none_returns_everything(mock_family):
    result = mock_family.get_payloads("testfam")
    assert len(result) == 3


def test_depth_basic_excludes_extended_and_aggressive(mock_family):
    result = mock_family.get_payloads("testfam", depth="basic")
    assert [p["payload"] for p in result] == ["p1"]


def test_depth_extended_is_cumulative(mock_family):
    result = mock_family.get_payloads("testfam", depth="extended")
    assert [p["payload"] for p in result] == ["p1", "p2"]


def test_depth_aggressive_returns_everything(mock_family):
    result = mock_family.get_payloads("testfam", depth="aggressive")
    assert [p["payload"] for p in result] == ["p1", "p2", "p3"]


def test_missing_depth_field_treated_as_basic(mock_family):
    # p1 n'a pas de champ "depth" -> doit sortir même au palier le plus bas
    result = mock_family.get_payloads("testfam", category="cat_a", depth="basic")
    assert any(p["payload"] == "p1" for p in result)
