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
    """Garde contre la régression trouvée en Task 3 : la signature win.ini
    avait perdu 2 des 3 alternatives de l'ancien code dur.

    Note (Task B1) : la catégorie 'windows' cible maintenant aussi d'autres
    fichiers (web.config, Unattend.xml) avec leurs propres signatures — on ne
    vérifie donc cette règle que sur les entrées qui ciblent bien win.ini."""
    from scanner.payloads import get_payloads
    windows_entries = get_payloads("lfi", category="windows")
    winini_entries = [p for p in windows_entries if "win.ini" in p["payload"]]
    assert winini_entries, "aucune entrée win.ini trouvée dans la catégorie windows"
    for p in winini_entries:
        assert "extensions" in p["signature"] and "mci extensions" in p["signature"]


def test_every_category_keeps_a_basic_tier_reachable_entry():
    """Non-régression Task B1 : l'enrichissement en volume (sqli/lfi/ssrf/xss) ne doit
    jamais faire disparaître le palier basic d'une catégorie. Une entrée est
    basic-reachable si elle n'a pas de champ 'depth', ou si 'depth' == 'basic'
    (get_payloads(depth='basic') doit alors la retourner)."""
    from scanner.payloads import PayloadCatalog
    for family in ("sqli", "lfi", "ssrf", "xss"):
        data = PayloadCatalog.load(family)
        for category, items in data["categories"].items():
            basics = [it for it in items if it.get("depth", "basic") == "basic"]
            assert basics, f"{family}/{category} n'a plus aucune entrée basic-tier"


def test_b1_new_entries_respect_field_shape_per_family():
    """Non-régression Task B1 : chaque entrée des 4 catalogues enrichis respecte la
    forme de champs attendue par son module consommateur.
    - Toutes familles : 'payload' et 'confidence_hint' présents, 'depth' (si présent)
      est une valeur connue.
    - lfi : 'signature' est obligatoire (load-bearing pour le matching de réponse),
      même si elle peut être une chaîne vide (cas documenté type php://input).
    - sqli/ssrf/xss : 'description' est obligatoire (lfi: optionnelle par convention)."""
    from scanner.payloads import PayloadCatalog
    for family in ("sqli", "lfi", "ssrf", "xss"):
        data = PayloadCatalog.load(family)
        for category, items in data["categories"].items():
            for item in items:
                assert "payload" in item, f"{family}/{category} : entrée sans 'payload'"
                assert "confidence_hint" in item, f"{family}/{category} : entrée sans 'confidence_hint'"
                if "depth" in item:
                    assert item["depth"] in ("basic", "extended", "aggressive")
                if family == "lfi":
                    assert "signature" in item, f"lfi/{category} : entrée sans 'signature'"
                else:
                    assert "description" in item, f"{family}/{category} : entrée sans 'description'"


def test_b1_xss_json_items_zero_unchanged_and_appended_only():
    """Non-régression Task B1 : xss.py utilise items[0] de chaque catégorie comme
    payload de repli (cf. _payload_catalog). Le volume ajouté ne doit jamais avoir
    reordonné ou remplacé la 1re entrée de chaque catégorie."""
    from scanner.payloads import get_payloads
    expected_first = {
        "html_context": "<script>alert(1)</script>",
        "attribute_context": "\" onmouseover=\"alert(1)",
        "js_context": "';alert(1);//",
        "url_context": "javascript:alert(1)",
        "svg_context": "<svg onload=alert(1)>",
        "img_context": "<img src=x onerror=alert(1)>",
    }
    for category, first_payload in expected_first.items():
        items = get_payloads("xss", category=category)
        assert items[0]["payload"] == first_payload, (
            f"xss.json/{category} : items[0] a changé — casse le payload de repli de xss.py"
        )


def test_b1_catalog_volume_increased_without_removing_existing_entries():
    """Non-régression Task B1 : vérifie que l'enrichissement en volume a bien
    augmenté le nombre d'entrées (pas de régression silencieuse qui viderait
    un fichier) pour chacune des 4 familles concernées par cette tâche."""
    from scanner.payloads import get_payloads
    # Bornes basses correspondant à l'état d'avant Task B1 (round précédent) :
    # cette tâche ne doit jamais faire redescendre le volume sous ces seuils.
    minimums = {"sqli": 20, "lfi": 15, "ssrf": 18, "xss": 25}
    for family, minimum in minimums.items():
        assert len(get_payloads(family)) >= minimum, (
            f"{family} : volume total retombé sous le seuil attendu post-Task-B1"
        )
