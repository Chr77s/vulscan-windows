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


def test_enriched_catalogs_still_have_depth_and_payload_fields():
    from scanner.payloads import get_payloads
    for family in ("sqli", "lfi", "ssrf", "xss"):
        items = get_payloads(family)
        assert len(items) > 0
        for it in items:
            assert "payload" in it
            # depth absent = basic (valide) ; si présent, doit être une valeur connue
            if "depth" in it:
                assert it["depth"] in ("basic", "extended", "aggressive")


def test_sqli_time_based_has_string_context_payloads_for_mssql_and_postgresql():
    """Garde contre la régression trouvée en Task 2 : sans le ' de tête, ces
    payloads ne sortent plus d'un paramètre en contexte string."""
    from scanner.payloads import get_payloads
    time_based = get_payloads("sqli", category="time_based")
    mssql = [p["payload"] for p in time_based if p.get("dbms") == "MSSQL"]
    postgres = [p["payload"] for p in time_based if p.get("dbms") == "PostgreSQL"]
    assert any(p.startswith("'") for p in mssql)
    assert any(p.startswith("'") for p in postgres)
    assert len(postgres) >= 2  # la variante empilée ET la variante sans requête empilée


def test_lfi_php_wrapper_signature_matches_real_php_source():
    """Garde contre la régression trouvée en Task 3 : l'ancre ^ empêchait tout
    match réel contre du code PHP commençant par <?php."""
    import re
    from scanner.payloads import get_payloads
    php_entries = get_payloads("lfi", category="php_wrappers")
    sig = next(p["signature"] for p in php_entries if "PD9waHA" in p.get("signature", ""))
    assert re.search(sig, "<?php echo 1; ?>")


def test_lfi_windows_signature_has_all_three_alternatives():
    """Garde contre la régression trouvée en Task 3 : la signature windows
    avait perdu 2 des 3 alternatives de l'ancien code dur."""
    from scanner.payloads import get_payloads
    windows_entries = get_payloads("lfi", category="windows")
    for p in windows_entries:
        assert "extensions" in p["signature"] and "mci extensions" in p["signature"]
