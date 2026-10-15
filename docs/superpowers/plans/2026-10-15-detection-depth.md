# Profondeur de détection (catalogue de payloads) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Brancher les modules actifs (`sqli`, `xss`, `lfi`, `ssrf`, puis 5 autres) sur le catalogue de payloads JSON déjà présent mais inutilisé, enrichir son contenu, et introduire un tag de profondeur `basic`/`extended`/`aggressive` propagé depuis le profil de scan de l'extension.

**Architecture:** `backend/scanner/payloads/catalog.py` (`get_payloads`) reste l'unique source de vérité des payloads ; chaque module appelle `get_payloads(family, category, depth=context.get("depth"))` au lieu de lire sa constante Python. La logique de détection/confirmation de chaque module ne change pas. `depth` voyage dans l'objet `context` déjà transmis sans changement de route entre l'extension et `/scanner/run`.

**Tech Stack:** Python 3 / Flask (backend), JavaScript vanilla MV3 (extension), pytest + pytest-mock.

**Spec:** [docs/superpowers/specs/2026-10-15-detection-depth-design.md](../specs/2026-10-15-detection-depth-design.md)

## Global Constraints

- `get_payloads(family, category=None, depth=None)` : `depth=None` doit renvoyer exactement ce que renvoie l'implémentation actuelle (zéro régression pour `dir_bruteforce.py`/`param_discovery.py`, qui n'appellent jamais avec `depth`).
- Paliers `basic` < `extended` < `aggressive`, filtrage **cumulatif** (palier X renvoie tout payload de palier ≤ X). Une entrée JSON sans champ `"depth"` vaut `basic`.
- Aucune nouvelle abstraction de test partagée entre modules — seule la source des payloads change, la logique de confirmation (diff Levenshtein, OOB, regex de signature) reste inchangée dans chaque module.
- Aucun changement de route backend. `depth` est une clé de plus dans l'objet `context` déjà transmis tel quel par `routes/scanner_engine.py:69-70` (`context = data.get("context", {})`).
- Tests backend : pytest + fixture `mocker` (pytest-mock), module instancié directement et `.scan(target, context)` appelé — convention de `backend/tests/test_modules.py`.
- Pas de contenu de payload propriétaire copié verbatim — uniquement des techniques publiques déjà largement documentées (OWASP, PayloadsAllTheThings, SecLists, ou transcription de payloads déjà présents dans ce repo).

## Review Focus

- Une entrée JSON sans champ `"depth"` doit être traitée comme `basic`, jamais exclue ni traitée comme couvrant tous les paliers — testé explicitement dans Task 1.
- `depth=None` (aucun filtrage demandé) doit renvoyer absolument toutes les entrées, y compris celles taguées `aggressive` — garde de non-régression pour les 2 appelants existants qui ne passent jamais `depth`.
- Un module branché sur le catalogue doit conserver exactement les champs dont sa logique de détection a besoin (ex: `dbms` pour le time-based SQLi, `signature` pour le LFI) — un test qui vérifie seulement "une Finding est levée" sans vérifier son contenu masquerait une perte de métadonnée.
- Les catégories `svg_context`/`img_context` de `xss.py` (codées en dur aujourd'hui, absentes de `xss.json`) ne doivent pas disparaître silencieusement en passant au catalogue — `xss.json` doit les gagner avant/pendant le branchement (Task 5), vérifié par un test qui les demande explicitement.
- `DEPTH_FOR_PROFILE` doit avoir un filet pour un profil inconnu/`custom` : jamais `undefined` (que `JSON.stringify` supprimerait silencieusement de l'objet `context`, désactivant le filtrage sans que personne ne le voie) — testé explicitement dans Task 6.

---

## Groupe 1 — Branchement des 4 modules existants

### Task 1: `catalog.py` — paramètre `depth`

**Files:**
- Modify: `backend/scanner/payloads/catalog.py`
- Test: `backend/tests/test_payload_catalog.py` (nouveau fichier)

**Interfaces:**
- Produces: `get_payloads(family: str, category: Optional[str] = None, depth: Optional[str] = None) -> List[Dict[str, Any]]` — utilisé par toutes les tâches suivantes.

- [ ] **Step 1: Écrire les tests (ils doivent échouer avant l'implémentation)**

```python
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
```

- [ ] **Step 2: Lancer les tests, vérifier qu'ils échouent**

Run: `pytest backend/tests/test_payload_catalog.py -v`
Expected: FAIL — `get_payloads() got an unexpected keyword argument 'depth'`

- [ ] **Step 3: Implémenter le filtrage cumulatif dans `catalog.py`**

```python
_DEPTH_ORDER = {"basic": 0, "extended": 1, "aggressive": 2}


def get_payloads(family: str, category: Optional[str] = None, depth: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retourne les payloads d'une famille (et optionnellement d'une catégorie),
    filtrés de façon cumulative par palier de profondeur si `depth` est fourni."""
    data = PayloadCatalog.load(family)
    categories = data.get("categories", {})
    if category:
        items = [{**item, "category": category} for item in categories.get(category, [])]
    else:
        items = []
        for cat_name, cat_items in categories.items():
            for item in cat_items:
                items.append({**item, "category": cat_name})
    if depth is None:
        return items
    max_rank = _DEPTH_ORDER.get(depth, _DEPTH_ORDER["aggressive"])
    return [it for it in items if _DEPTH_ORDER.get(it.get("depth", "basic"), 0) <= max_rank]
```

- [ ] **Step 4: Lancer les tests, vérifier qu'ils passent**

Run: `pytest backend/tests/test_payload_catalog.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/payloads/catalog.py backend/tests/test_payload_catalog.py
git commit -m "feat(payloads): add cumulative depth filtering to get_payloads()"
```

---

### Task 2: Brancher `sqli.py` sur le catalogue

**Files:**
- Modify: `backend/scanner/modules/sqli.py` (constante `TIME_PAYLOADS` lignes 49-55 ; boucle `scan()` lignes 129-183)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("sqli", category="time_based", depth=...)` → entrées `{"payload", "description", "confidence_hint", "dbms", "category"}` ; `get_payloads("sqli", category="boolean_blind", depth=...)` → entrées `{"payload", "description", "confidence_hint", "expects", "category"}`.

- [ ] **Step 1: Écrire le test**

```python
def test_sqli_time_based_uses_catalog_payloads(mocker):
    """Le module doit consommer get_payloads('sqli', 'time_based'), pas sa constante en dur."""
    from scanner.modules.sqli import SqliModule
    import scanner.modules.sqli as sqli_mod

    spy = mocker.spy(sqli_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, headers={}, text="no error here")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    SqliModule().scan("http://a?id=1", {})

    calls = [c for c in spy.call_args_list if c.args and c.args[0] == "sqli"]
    assert any(c.kwargs.get("category") == "time_based" or (len(c.args) > 1 and c.args[1] == "time_based") for c in calls)
```

- [ ] **Step 2: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_modules.py::test_sqli_time_based_uses_catalog_payloads -v`
Expected: FAIL — `get_payloads` jamais appelé (le module utilise encore `TIME_PAYLOADS`)

- [ ] **Step 3: Remplacer `TIME_PAYLOADS` par un appel catalogue**

Importer `from scanner.payloads import get_payloads` en tête de fichier. Dans `scan()`, juste avant la boucle `for param_name, base_value in params.items()` (section 2B), construire la liste localement :

```python
time_payloads = [
    (p["payload"], p.get("dbms", "?"), 5)
    for p in get_payloads("sqli", category="time_based", depth=context.get("depth"))
]
```

puis remplacer `for payload, dbms, sleep_s in self.TIME_PAYLOADS:` par `for payload, dbms, sleep_s in time_payloads:`. Supprimer la constante de classe `TIME_PAYLOADS` (plus utilisée). `sleep_s` n'est utilisé que dans le texte de la `description` — la valeur fixe `5` matche `sqli.json` (tous les `time_based` sont des sleep 5s) ; si un payload custom a une autre durée, le texte de description reste approximatif, ce qui est sans conséquence (champ informatif, pas un seuil de décision — `TIME_THRESHOLD` reste la vraie valeur de comparaison).

- [ ] **Step 4: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_modules.py::test_sqli_time_based_uses_catalog_payloads -v`
Expected: PASS

- [ ] **Step 5: Vérifier la non-régression de la suite complète du module**

Run: `pytest backend/tests/test_modules.py backend/tests/test_auth_propagation.py -k sqli -v`
Expected: PASS (aucun test existant cassé)

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/modules/sqli.py backend/tests/test_modules.py
git commit -m "feat(sqli): consume payload catalog instead of hardcoded TIME_PAYLOADS"
```

---

### Task 3: Brancher `lfi.py` sur le catalogue

**Files:**
- Modify: `backend/scanner/modules/lfi.py` (constante `PAYLOADS` lignes 32-39 ; boucle `scan()` lignes 85-117)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("lfi", depth=...)` (toutes catégories aplaties) → entrées `{"payload", "signature", "confidence_hint", "category"}`. `category` vaut `linux`/`windows`/`php_wrappers` — utilisé comme `os_label`.

- [ ] **Step 1: Écrire le test**

```python
def test_lfi_uses_catalog_payloads_and_keeps_signature_field(mocker):
    """Le module doit lire payload+signature du catalogue, pas de PAYLOADS en dur."""
    from scanner.modules.lfi import LfiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="nothing interesting")
    confirming = mocker.Mock(status_code=200, headers={}, text="root:x:0:0:root:/root:/bin/bash")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 20)

    findings = LfiModule().scan("http://a?file=x", {})

    assert any(f.type == "path-traversal" and "../../../../etc/passwd" in f.payload for f in findings)
```

- [ ] **Step 2: Lancer le test, vérifier qu'il échoue ou passe par coïncidence**

Run: `pytest backend/tests/test_modules.py::test_lfi_uses_catalog_payloads_and_keeps_signature_field -v`
Expected: PASS aujourd'hui (le payload existe déjà en dur) — ce test sert de garde de non-régression pendant le refactor, pas d'un test rouge→vert classique. Noter ce fait et continuer.

- [ ] **Step 3: Remplacer `PAYLOADS` par un appel catalogue**

Importer `from scanner.payloads import get_payloads`. Remplacer la constante de classe `PAYLOADS` par une construction en début de `scan()` :

```python
payloads = [
    (p["payload"], p.get("signature", ""), p.get("category", "?"))
    for p in get_payloads("lfi", depth=context.get("depth"))
]
```

puis `for payload, sig_pattern, os_label in self.PAYLOADS:` devient `for payload, sig_pattern, os_label in payloads:`. Un payload avec `signature` vide (`php://input` dans `lfi.json`) ne doit jamais matcher via `re.search("", r.text)` qui serait toujours vrai — garder le comportement actuel en sautant les entrées à signature vide : `if not sig_pattern: continue` avant le `re.search`.

- [ ] **Step 4: Lancer le test, vérifier qu'il passe toujours**

Run: `pytest backend/tests/test_modules.py::test_lfi_uses_catalog_payloads_and_keeps_signature_field -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/lfi.py backend/tests/test_modules.py
git commit -m "feat(lfi): consume payload catalog instead of hardcoded PAYLOADS"
```

---

### Task 4: Brancher `ssrf.py` sur le catalogue

**Files:**
- Modify: `backend/scanner/modules/ssrf.py` (constante `PAYLOADS` lignes 34-40 ; boucle `scan()` lignes 110-173)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("ssrf", depth=...)` (toutes catégories aplaties) → entrées `{"payload", "description", "confidence_hint", "category"}`. `description` remplace `label`.

- [ ] **Step 1: Écrire le test**

```python
def test_ssrf_uses_catalog_payloads(mocker):
    from scanner.modules.ssrf import SsrfModule
    import scanner.modules.ssrf as ssrf_mod

    spy = mocker.spy(ssrf_mod, "get_payloads")
    baseline = mocker.Mock(status_code=200, headers={}, text="baseline body")
    mocker.patch("scanner.core.http.requests.request", return_value=baseline)
    mocker.patch("scanner.core.oob.OOBCanary.wait_for_hit", return_value=False)

    SsrfModule().scan("http://a?url=http://x", {})

    assert spy.call_args_list, "get_payloads n'a jamais été appelé — PAYLOADS en dur toujours utilisé ?"
    assert any(c.args and c.args[0] == "ssrf" for c in spy.call_args_list)
```

- [ ] **Step 2: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_modules.py::test_ssrf_uses_catalog_payloads -v`
Expected: FAIL — `get_payloads` jamais appelé

- [ ] **Step 3: Remplacer `PAYLOADS` par un appel catalogue**

Importer `from scanner.payloads import get_payloads`. Remplacer la constante de classe par :

```python
payloads = [
    (p["payload"], p.get("description", "?"))
    for p in get_payloads("ssrf", depth=context.get("depth"))
]
```

puis `for payload, label in self.PAYLOADS:` devient `for payload, label in payloads:`.

- [ ] **Step 4: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_modules.py::test_ssrf_uses_catalog_payloads -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/ssrf.py backend/tests/test_modules.py
git commit -m "feat(ssrf): consume payload catalog instead of hardcoded PAYLOADS"
```

---

### Task 5: Réconcilier `xss.json` puis brancher `xss.py`

**Files:**
- Modify: `backend/scanner/payloads/xss.json` (ajouter `svg_context`/`img_context`)
- Modify: `backend/scanner/modules/xss.py` (constante `PAYLOAD_CATALOG` lignes 31-38 ; usage ligne 70)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("xss", category=<ctx>, depth=...)` pour `<ctx>` dans `{html_context, attribute_context, js_context, url_context, svg_context, img_context}`.

- [ ] **Step 1: Ajouter les catégories manquantes à `xss.json`**

Dans `backend/scanner/payloads/xss.json`, ajouter aux `categories` existantes (ne pas toucher `polyglot` ni les 4 catégories déjà présentes) :

```json
    "svg_context": [
      {"payload": "<svg onload=alert(1)>", "description": "SVG onload", "confidence_hint": 85}
    ],
    "img_context": [
      {"payload": "<img src=x onerror=alert(1)>", "description": "IMG onerror", "confidence_hint": 85}
    ]
```

(valeurs transcrites depuis `PAYLOAD_CATALOG["svg_context"]`/`["img_context"]` actuels de `xss.py` — pas de nouveau contenu inventé à ce stade, l'enrichissement vient à la Task 7.)

- [ ] **Step 2: Écrire le test**

```python
def test_xss_json_has_svg_and_img_context():
    from scanner.payloads import get_payloads
    assert get_payloads("xss", category="svg_context")
    assert get_payloads("xss", category="img_context")


def test_xss_module_uses_catalog_for_all_contexts(mocker):
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod

    spy = mocker.spy(xss_mod, "get_payloads")
    marker_body = mocker.Mock(status_code=200, headers={}, text="<div>MARKERHERE</div>")

    def fake_get(url, context, **kw):
        return marker_body, {}, {}
    mocker.patch("scanner.core.http.get", side_effect=lambda *a, **k: marker_body)

    XssModule().scan("http://a?q=test", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé — PAYLOAD_CATALOG en dur toujours utilisé ?"
```

- [ ] **Step 3: Lancer les tests, vérifier qu'ils échouent (le 2e) / passent (le 1er après Step 1)**

Run: `pytest backend/tests/test_modules.py -k "xss_json or xss_module_uses_catalog" -v`
Expected: `test_xss_json_has_svg_and_img_context` PASS, `test_xss_module_uses_catalog_for_all_contexts` FAIL

- [ ] **Step 4: Remplacer `PAYLOAD_CATALOG` par un appel catalogue**

Importer `from scanner.payloads import get_payloads`. Remplacer la constante de classe `PAYLOAD_CATALOG` (dict) par une méthode qui construit l'équivalent à la demande :

```python
_CONTEXTS = ("html_context", "attribute_context", "js_context", "url_context", "svg_context", "img_context")

def _payload_catalog(self, depth):
    out = {}
    for ctx in self._CONTEXTS:
        items = get_payloads("xss", category=ctx, depth=depth)
        if items:
            out[ctx] = items[0]["payload"]
    return out
```

Dans `scan()`, avant la boucle `for param_name, base_value in params.items()`, ajouter `catalog = self._payload_catalog(context.get("depth"))`. Remplacer les 2 usages de `self.PAYLOAD_CATALOG` (lignes ~70 et ~85) par `catalog`.

- [ ] **Step 5: Lancer les tests, vérifier qu'ils passent**

Run: `pytest backend/tests/test_modules.py -k "xss_json or xss_module_uses_catalog" -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/payloads/xss.json backend/scanner/modules/xss.py backend/tests/test_modules.py
git commit -m "feat(xss): reconcile svg/img contexts into xss.json, consume catalog"
```

---

### Task 6: Plomberie `depth` dans l'extension

**Files:**
- Modify: `extension/src/background/service-worker.js` (ajout const après `SCAN_PROFILES`, ligne ~307 ; modification de `runActiveModules`, ligne ~370)
- Test: nouveau fichier de test JS minimal (voir Step 1 — ce projet n'a pas de runner JS existant, le test est un script Node autonome exécuté manuellement, suivant le pattern déjà utilisé dans ce projet pour `verify_trendcache.mjs`)

**Interfaces:**
- Produces: `DEPTH_FOR_PROFILE` (const), et la clé `depth` dans l'objet `context` envoyé à `POST /scanner/run`.

- [ ] **Step 1: Écrire le script de vérification**

```js
// scratchpad: verify_depth_for_profile.mjs
const DEPTH_FOR_PROFILE = {
  quick: "basic", standard: "extended", deep: "aggressive",
  owasp: "aggressive", api: "extended",
};

function resolveDepth(profile) {
  return DEPTH_FOR_PROFILE[profile] || "extended";
}

console.assert(resolveDepth("quick") === "basic", "FAIL quick");
console.assert(resolveDepth("standard") === "extended", "FAIL standard");
console.assert(resolveDepth("deep") === "aggressive", "FAIL deep");
console.assert(resolveDepth("owasp") === "aggressive", "FAIL owasp");
console.assert(resolveDepth("api") === "extended", "FAIL api");
console.assert(resolveDepth("custom") === "extended", "FAIL custom fallback");
console.assert(resolveDepth(undefined) === "extended", "FAIL undefined fallback");
console.assert(JSON.stringify({ depth: resolveDepth("custom") }).includes('"depth":"extended"'), "FAIL JSON.stringify never drops depth");
console.log("ALL ASSERTIONS PASSED");
```

Run: `node verify_depth_for_profile.mjs` (depuis le scratchpad)
Expected: PASS une fois la Step 2 appliquée dans le vrai fichier — ce script valide la logique avant de l'intégrer, il ne reste pas dans le repo.

- [ ] **Step 2: Ajouter `DEPTH_FOR_PROFILE` et l'injecter dans `context`**

Dans `service-worker.js`, juste après la définition de `SCAN_PROFILES` (ligne ~307) :

```js
// Palier de profondeur de payloads par profil (backend, découplé des 5 profils).
const DEPTH_FOR_PROFILE = {
  quick: "basic", standard: "extended", deep: "aggressive",
  owasp: "aggressive", api: "extended",
};
```

Dans `runActiveModules(cfg, url)` (ligne ~370), modifier l'objet `context` du body :

```js
context: {
  ...(auth ? { auth } : {}),
  rate_limit_per_sec: cfg.requestsPerSecond,
  depth: DEPTH_FOR_PROFILE[cfg.scanProfile] || "extended",
},
```

- [ ] **Step 3: Vérifier à la main (pas de runner JS automatisé dans ce projet)**

Run: `node -c extension/src/background/service-worker.js` (vérifie juste l'absence d'erreur de syntaxe — convention déjà utilisée dans ce repo pour valider les scripts classiques sans module bundler)
Expected: aucune sortie, code de sortie 0

- [ ] **Step 4: Commit**

```bash
git add extension/src/background/service-worker.js
git commit -m "feat(extension): map scan profile to backend payload depth tier"
```

---

## Groupe 2 — Enrichissement du contenu

### Task 7: Tagger `depth` et enrichir `sqli.json`/`lfi.json`/`ssrf.json`/`xss.json`

**Files:**
- Modify: `backend/scanner/payloads/sqli.json`, `lfi.json`, `ssrf.json`, `xss.json`
- Test: `backend/tests/test_payload_catalog.py`

**Interfaces:**
- Consumes: aucune nouvelle interface — ce sont des données, pas du code.

- [ ] **Step 1: Tagger toutes les entrées existantes par palier**

Pour chacun des 4 fichiers, ajouter `"depth"` à chaque entrée existante selon l'heuristique de la spec §4.3 : erreurs simples / loopback / contextes HTML de base → `"basic"` ; variantes multiples ou légèrement intrusives (boolean_blind, UNION, schemes exotiques) → `"extended"` ; time-based et payloads lents/exotiques (gopher, dict, metadata cloud) → `"aggressive"`.

- [ ] **Step 2: Rechercher et ajouter des payloads supplémentaires par catégorie**

Utiliser la recherche web (OWASP Testing Guide, PayloadsAllTheThings, SecLists) pour ajouter 2 à 5 payloads supplémentaires par catégorie existante, dans le même format que les entrées actuelles (`payload`, `description`, `confidence_hint`, `depth`, + champ spécifique à la famille — `dbms`/`signature`/rien). Ne pas copier de contenu propriétaire — uniquement des techniques génériques déjà publiées par ces références. Exemples de pistes (non exhaustif, à l'implémenteur de vérifier l'exactitude technique au moment de l'écrire) : variantes d'échappement SQLi par SGBD, contextes XSS supplémentaires (polyglots courts), variantes d'encodage LFI (URL-encoded, null byte historique), schémas SSRF additionnels (`ftp://`, IPv6 obfusqué, décimal/octal IP).

- [ ] **Step 3: Écrire un test de non-régression de volume/forme**

```python
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
```

- [ ] **Step 4: Lancer le test**

Run: `pytest backend/tests/test_payload_catalog.py::test_enriched_catalogs_still_have_depth_and_payload_fields -v`
Expected: PASS

- [ ] **Step 5: Lancer la suite complète pour vérifier qu'aucun module branché (Tasks 2-5) ne casse**

Run: `pytest backend/tests/test_modules.py backend/tests/test_payload_catalog.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/payloads/sqli.json backend/scanner/payloads/lfi.json backend/scanner/payloads/ssrf.json backend/scanner/payloads/xss.json backend/tests/test_payload_catalog.py
git commit -m "feat(payloads): tag depth tiers and enrich sqli/lfi/ssrf/xss catalogs"
```

---

## Groupe 3 — Extension à 5 autres modules

### Task 8: `command_injection.py` + nouveau `command_injection.json`

**Files:**
- Create: `backend/scanner/payloads/command_injection.json`
- Modify: `backend/scanner/modules/command_injection.py` (constante `PAYLOADS` lignes 33-42 ; boucle lignes 55-90)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("command_injection", depth=...)` → entrées `{"payload", "signature", "confidence_hint", "category"}`.

- [ ] **Step 1: Créer le catalogue (transcription des payloads existants + tags)**

```json
{
  "family": "command_injection",
  "version": "1.0.0",
  "categories": {
    "separators": [
      {"payload": "; id",       "signature": "uid=\\d+\\(\\w+\\)", "confidence_hint": 90, "depth": "basic"},
      {"payload": "|id",        "signature": "uid=\\d+\\(\\w+\\)", "confidence_hint": 90, "depth": "basic"},
      {"payload": "&& id",      "signature": "uid=\\d+\\(\\w+\\)", "confidence_hint": 90, "depth": "basic"},
      {"payload": "`id`",       "signature": "uid=\\d+\\(\\w+\\)", "confidence_hint": 85, "depth": "extended"},
      {"payload": "$(id)",      "signature": "uid=\\d+\\(\\w+\\)", "confidence_hint": 85, "depth": "extended"}
    ],
    "recon": [
      {"payload": "; uname -a", "signature": "Linux|Darwin", "confidence_hint": 80, "depth": "extended"},
      {"payload": "& whoami",   "signature": "\\\\?\\w+",    "confidence_hint": 70, "depth": "extended"},
      {"payload": "| ipconfig", "signature": "Windows IP Configuration", "confidence_hint": 80, "depth": "aggressive"}
    ]
  }
}
```

- [ ] **Step 2: Écrire le test**

```python
def test_command_injection_uses_catalog(mocker):
    from scanner.modules.command_injection import CommandInjectionModule
    import scanner.modules.command_injection as ci_mod

    spy = mocker.spy(ci_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, headers={}, text="no match")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    CommandInjectionModule().scan("http://a?cmd=ls", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"
```

- [ ] **Step 3: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_modules.py::test_command_injection_uses_catalog -v`
Expected: FAIL

- [ ] **Step 4: Brancher le module**

Importer `from scanner.payloads import get_payloads`. Remplacer la constante `PAYLOADS` par, en début de `scan()` :

```python
payloads = [
    (p["payload"], p.get("signature", ""))
    for p in get_payloads("command_injection", depth=context.get("depth"))
]
```

puis `for payload, sig in self.PAYLOADS:` devient `for payload, sig in payloads:`.

- [ ] **Step 5: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_modules.py::test_command_injection_uses_catalog -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/payloads/command_injection.json backend/scanner/modules/command_injection.py backend/tests/test_modules.py
git commit -m "feat(command-injection): add payload catalog and consume it"
```

---

### Task 9: `ssti.py` + nouveau `ssti.json`

**Files:**
- Create: `backend/scanner/payloads/ssti.json`
- Modify: `backend/scanner/modules/ssti.py` (constante `PROBES` lignes 23-28 ; boucle lignes 47-75)
- Test: `backend/tests/test_ssti.py`

**Interfaces:**
- Consumes: `get_payloads("ssti", depth=...)` → entrées `{"payload", "engine", "expected", "confidence_hint", "category"}`.

- [ ] **Step 1: Créer le catalogue**

```json
{
  "family": "ssti",
  "version": "1.0.0",
  "categories": {
    "arithmetic_probe": [
      {"payload": "{{1337*7331}}", "engine": "Jinja2/Twig",          "expected": "9801547", "confidence_hint": 90, "depth": "basic"},
      {"payload": "${1337*7331}",  "engine": "Freemarker/Velocity",  "expected": "9801547", "confidence_hint": 90, "depth": "basic"},
      {"payload": "#{1337*7331}",  "engine": "Thymeleaf (SpEL)",     "expected": "9801547", "confidence_hint": 85, "depth": "extended"},
      {"payload": "*{1337*7331}",  "engine": "Thymeleaf (alt)",      "expected": "9801547", "confidence_hint": 85, "depth": "extended"}
    ]
  }
}
```

(mêmes valeurs `1337*7331`/`9801547` que l'existant — cf. commentaire déjà présent dans `ssti.py:20-22` expliquant pourquoi ce couple précis a été choisi ; ne pas le changer.)

- [ ] **Step 2: Écrire le test**

```python
def test_ssti_uses_catalog_payloads(mocker):
    from scanner.modules.ssti import SstiModule
    import scanner.modules.ssti as ssti_mod

    spy = mocker.spy(ssti_mod, "get_payloads")
    baseline = mocker.Mock(status_code=200, headers={}, text="baseline")
    mocker.patch("scanner.core.http.requests.request", return_value=baseline)

    SstiModule().scan("http://a?q=x", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"
```

- [ ] **Step 3: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_ssti.py::test_ssti_uses_catalog_payloads -v`
Expected: FAIL

- [ ] **Step 4: Brancher le module**

Importer `from scanner.payloads import get_payloads`. Remplacer `PROBES` par, en début de `scan()` :

```python
probes = [
    (p["payload"], p.get("engine", "?"), p.get("expected", ""))
    for p in get_payloads("ssti", depth=context.get("depth"))
]
```

puis `for payload, engine, expected in self.PROBES:` devient `for payload, engine, expected in probes:`.

- [ ] **Step 5: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_ssti.py -v`
Expected: PASS (ce test + les tests `test_ssti.py` déjà existants)

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/payloads/ssti.json backend/scanner/modules/ssti.py backend/tests/test_ssti.py
git commit -m "feat(ssti): add payload catalog and consume it"
```

---

### Task 10: `nosqli.py` + nouveau `nosqli.json`

**Files:**
- Create: `backend/scanner/payloads/nosqli.json`
- Modify: `backend/scanner/modules/nosqli.py` (constante `OPERATOR_PAYLOADS` ligne 19 ; boucle lignes 38-81)
- Test: `backend/tests/test_nosqli.py`

**Interfaces:**
- Consumes: `get_payloads("nosqli", depth=...)` → entrées `{"payload", "confidence_hint", "category"}` où `payload` peut être une chaîne OU un objet JSON (le schéma du catalogue accepte une valeur non-string pour ce champ, cf. non-objectif spec 4.1 — pas de changement de schéma, juste une valeur de type différent).

- [ ] **Step 1: Créer le catalogue**

```json
{
  "family": "nosqli",
  "version": "1.0.0",
  "categories": {
    "mongo_operators": [
      {"payload": {"$gt": ""},   "confidence_hint": 85, "depth": "basic"},
      {"payload": {"$ne": null}, "confidence_hint": 85, "depth": "basic"},
      {"payload": "';return true;//", "confidence_hint": 70, "depth": "extended"}
    ]
  }
}
```

- [ ] **Step 2: Écrire le test**

```python
def test_nosqli_uses_catalog_payloads(mocker):
    from scanner.modules.nosqli import NoSqliModule
    import scanner.modules.nosqli as nosqli_mod

    spy = mocker.spy(nosqli_mod, "get_payloads")
    baseline = mocker.Mock(status_code=401, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=baseline)

    NoSqliModule().scan("http://a", {"crawled": {"api_endpoints": ["http://a/login"]}})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"
```

- [ ] **Step 3: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_nosqli.py::test_nosqli_uses_catalog_payloads -v`
Expected: FAIL

- [ ] **Step 4: Brancher le module**

Importer `from scanner.payloads import get_payloads`. Remplacer la constante de classe `OPERATOR_PAYLOADS` par un calcul dans `_test_endpoint` (ou `scan`, en le passant en paramètre) :

```python
operator_payloads = [p["payload"] for p in get_payloads("nosqli", depth=context.get("depth"))]
```

puis `for payload in self.OPERATOR_PAYLOADS:` devient `for payload in operator_payloads:`. `_test_endpoint` reçoit `operator_payloads` en paramètre supplémentaire (calculé une fois dans `scan()`, pas par endpoint, pour éviter de relire le catalogue en boucle).

- [ ] **Step 5: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_nosqli.py -v`
Expected: PASS (ce test + les tests `test_nosqli.py` déjà existants)

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/payloads/nosqli.json backend/scanner/modules/nosqli.py backend/tests/test_nosqli.py
git commit -m "feat(nosqli): add payload catalog and consume it"
```

---

### Task 11: `xxe.py` + nouveau `xxe.json` (enrichissement de variété)

**Files:**
- Create: `backend/scanner/payloads/xxe.json`
- Modify: `backend/scanner/modules/xxe.py` (constante `PAYLOAD` singulière ligne 27-31 ; corps de `scan()` lignes 44-96)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("xxe", depth=...)` → entrées `{"payload", "confidence_hint", "category"}`.

Aujourd'hui `xxe.py` n'a qu'**un seul** payload codé en dur — cette tâche introduit donc à la fois le branchement catalogue ET sa première variété (techniques XXE publiques standard, pas de recherche web nécessaire ici).

- [ ] **Step 1: Créer le catalogue avec 4 variantes connues**

```json
{
  "family": "xxe",
  "version": "1.0.0",
  "categories": {
    "system_entity": [
      {"payload": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]>\n<root>&xxe;</root>\n", "confidence_hint": 90, "depth": "basic"},
      {"payload": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]>\n<root>&xxe;</root>\n", "confidence_hint": 85, "depth": "basic"},
      {"payload": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>\n<root>&xxe;</root>\n", "confidence_hint": 90, "depth": "extended"}
    ],
    "parameter_entity": [
      {"payload": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/hostname\"> %xxe;]>\n<root>ok</root>\n", "confidence_hint": 70, "depth": "aggressive"}
    ]
  }
}
```

- [ ] **Step 2: Écrire le test**

```python
def test_xxe_uses_catalog_payloads(mocker):
    from scanner.modules.xxe import XxeModule
    import scanner.modules.xxe as xxe_mod

    spy = mocker.spy(xxe_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, text="no doctype error here")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    XxeModule().scan("http://a/api.xml", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"


def test_xxe_still_detects_file_scheme_reflection(mocker):
    from scanner.modules.xxe import XxeModule
    fake = mocker.Mock(status_code=200, text="leaked: file:///etc/hostname contents here")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    findings = XxeModule().scan("http://a/api.xml", {})
    assert any(f.type == "xxe" and f.severity == "critical" for f in findings)
```

- [ ] **Step 3: Lancer les tests, vérifier que le 1er échoue**

Run: `pytest backend/tests/test_modules.py -k xxe -v`
Expected: `test_xxe_uses_catalog_payloads` FAIL, `test_xxe_still_detects_file_scheme_reflection` PASS (comportement déjà correct avant refactor)

- [ ] **Step 4: Brancher le module — boucler sur plusieurs payloads au lieu d'un seul**

Importer `from scanner.payloads import get_payloads`. Remplacer la constante `PAYLOAD` (singulière) et le bloc `try/except` unique de `scan()` par une boucle qui essaie chaque payload du catalogue jusqu'à la première confirmation (même structure que `lfi.py`/`command_injection.py` — un seul `http.post` par payload, on arrête au premier match) :

```python
for p in get_payloads("xxe", depth=context.get("depth")):
    payload = p["payload"]
    try:
        r, req_ev, resp_ev = http.post(target, context, capture=True, data=payload, timeout=8, headers={
            "Content-Type": "application/xml", "User-Agent": "VulnScan/1.2",
        })
        if r is None:
            continue
        body = r.text
    except Exception:
        continue

    if re.search(r"file://[a-z0-9/.\-_]+", body, re.I):
        findings.append(Finding(..., payload=payload, ...))  # même structure qu'aujourd'hui
        break
    elif re.search(r"xml.*(entity|doctype)", body, re.I):
        findings.append(Finding(..., payload=payload, ...))  # idem
        break
return findings
```

(Les deux blocs `Finding(...)` existants restent identiques, seule la source du payload et la boucle changent — pas de nouvel algorithme de détection.)

- [ ] **Step 5: Lancer les tests, vérifier qu'ils passent**

Run: `pytest backend/tests/test_modules.py -k xxe -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/payloads/xxe.json backend/scanner/modules/xxe.py backend/tests/test_modules.py
git commit -m "feat(xxe): add payload catalog with 4 variants, loop instead of single payload"
```

---

### Task 12: Renommer `headers.json` → `header_injection.json`, brancher `header_injection.py`

**Files:**
- Create: `backend/scanner/payloads/header_injection.json` (contenu repris de `headers.json`, champ `"family"` corrigé)
- Delete: `backend/scanner/payloads/headers.json`
- Modify: `backend/scanner/modules/header_injection.py` (méthode `_payloads_for` lignes 183-207 ; usage ligne 75)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("header_injection", category=<header_name_lower_with_underscores>, depth=...)` → entrées `{"payload", "type", "description", "confidence_hint", "category"}`.

`headers.json` existe déjà avec quasiment la structure exacte dont ce module a besoin (catégories `user_agent`/`referer`/`x_forwarded_for`/`host`/`cookie`, champ `type` déjà présent) — mais il n'a jamais été branché (c'est en fait le payload de `header_injection.py`, pas de `headers.py`, cf. spec §1).

- [ ] **Step 1: Créer `header_injection.json` (copie de `headers.json` + `"family"` corrigé)**

```json
{
  "family": "header_injection",
  "version": "1.0.0",
  "categories": {
    "user_agent": [
      {"payload": "Mozilla/5.0 <script>alert(1)</script>",         "type": "xss",  "description": "XSS dans logs/analytics", "confidence_hint": 80, "depth": "basic"},
      {"payload": "Mozilla/5.0 ' OR 1=1-- ",                       "type": "sqli", "description": "SQLi dans UA stocké en DB", "confidence_hint": 75, "depth": "basic"},
      {"payload": "Mozilla/5.0\r\nX-Injected: yes",                "type": "crlf", "description": "CRLF injection", "confidence_hint": 70, "depth": "extended"}
    ],
    "referer": [
      {"payload": "https://evil.com/<svg onload=alert(1)>",        "type": "xss",      "description": "XSS via Referer affiché", "confidence_hint": 70, "depth": "basic"},
      {"payload": "https://evil.example.com",                      "type": "host-injection", "description": "Referer canary", "confidence_hint": 60, "depth": "basic"}
    ],
    "x_forwarded_for": [
      {"payload": "127.0.0.1' OR 1=1-- ",                          "type": "sqli",  "description": "SQLi via IP loggée en DB", "confidence_hint": 75, "depth": "extended"},
      {"payload": "<svg onload=alert(1)>",                         "type": "xss",   "description": "XSS dans logs admin", "confidence_hint": 70, "depth": "basic"}
    ],
    "host": [
      {"payload": "evil.example.com",                              "type": "host-injection", "description": "Host canary", "confidence_hint": 75, "depth": "basic"}
    ],
    "cookie": [
      {"payload": "admin=true",                                     "type": "privesc", "description": "Privesc via cookie", "confidence_hint": 50, "depth": "extended"}
    ]
  }
}
```

(payload XSS de `user_agent`/`referer`/`x_forwarded_for` utilise `<svg onload=alert(1)>`/`<script>` statique — le module injecte lui-même un marqueur unique `{mark}` au moment de l'envoi en remplaçant dans le code, pas dans le JSON, cf. Step 3.)

- [ ] **Step 2: Supprimer l'ancien fichier**

```bash
git rm backend/scanner/payloads/headers.json
```

- [ ] **Step 3: Écrire le test**

```python
def test_header_injection_uses_catalog(mocker):
    from scanner.modules.header_injection import HeaderInjectionModule
    import scanner.modules.header_injection as hi_mod

    spy = mocker.spy(hi_mod, "get_payloads")
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)

    HeaderInjectionModule().scan("http://a", {})
    assert spy.call_args_list, "get_payloads n'a jamais été appelé"
```

- [ ] **Step 4: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_modules.py::test_header_injection_uses_catalog -v`
Expected: FAIL

- [ ] **Step 5: Brancher `_payloads_for`**

Importer `from scanner.payloads import get_payloads`. Remplacer le corps de `_payloads_for(header_name, mark)` :

```python
@staticmethod
def _payloads_for(header_name: str, mark: str, depth=None):
    category = header_name.lower().replace("-", "_")
    out = []
    for p in get_payloads("header_injection", category=category, depth=depth):
        value = p["payload"].replace("{MARK}", mark) if "{MARK}" in p["payload"] else p["payload"]
        # Les payloads XSS statiques n'ont pas de marqueur dans le JSON — en ajouter un
        # pour garder la détection fiable par reflet (comme avant ce refactor).
        if p["type"] == "xss" and mark not in value:
            value = value.replace("alert(1)", f"alert({mark})")
        out.append((value, p["type"], p.get("description", "")))
    return out
```

Mettre à jour l'appelant (`_test_header`, ligne ~75) : `payloads = self._payloads_for(header_name, mark, context.get("depth"))`. `_test_header` doit recevoir `context` (déjà le cas, c'est un paramètre existant de la méthode).

- [ ] **Step 6: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_modules.py::test_header_injection_uses_catalog -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add backend/scanner/payloads/header_injection.json backend/scanner/modules/header_injection.py backend/tests/test_modules.py
git rm backend/scanner/payloads/headers.json
git commit -m "feat(header-injection): rename headers.json, consume catalog"
```

---

### Task 13: Enrichir `json_fuzzer.py` via les catalogues `sqli`/`lfi`

**Files:**
- Modify: `backend/scanner/modules/json_fuzzer.py` (constante `PAYLOADS` lignes 37-42 ; boucle lignes 90-167)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("sqli", category="error_based", depth=...)`, `get_payloads("lfi", category="linux", depth=...)`.

Ce module mélange XSS/SQLi/NoSQLi/LFI dans un seul body JSON testé par clé. Le payload XSS utilise un gabarit `{MARK}` substitué dynamiquement par requête (fiabilité de détection) — **ce payload reste codé en dur**, le catalogue `xss.json` ne porte pas ce gabarit et l'ajouter serait hors de la portée "étendre le pattern existant" de cette tâche. Seules les variantes **SQLi** et **LFI** (qui n'ont pas besoin de `{MARK}`, elles matchent sur signature fixe) sont enrichies depuis les catalogues déjà branchés en Groupe 1.

- [ ] **Step 1: Écrire le test**

```python
def test_json_fuzzer_pulls_extra_sqli_and_lfi_payloads(mocker):
    from scanner.modules.json_fuzzer import JsonFuzzerModule
    import scanner.modules.json_fuzzer as jf_mod

    spy = mocker.spy(jf_mod, "get_payloads")
    r_base = mocker.Mock(status_code=200, text="{}")
    mocker.patch("scanner.core.http.requests.request", return_value=r_base)

    JsonFuzzerModule().scan("http://a/api/x", {"crawled": {"api_endpoints": ["http://a/api/x"]}})
    families_called = {c.args[0] for c in spy.call_args_list if c.args}
    assert families_called >= {"sqli", "lfi"}
```

- [ ] **Step 2: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_modules.py::test_json_fuzzer_pulls_extra_sqli_and_lfi_payloads -v`
Expected: FAIL

- [ ] **Step 3: Étendre `PAYLOADS` avec les variantes catalogue au lieu de le remplacer**

Importer `from scanner.payloads import get_payloads`. Garder les 4 entrées actuelles de `PAYLOADS` telles quelles (le gabarit XSS et le marqueur `nosqli` restent spéciaux). Dans `scan()`, juste avant la boucle sur `endpoints`, construire la liste étendue :

```python
def _build_payload_defs(self, depth):
    extra = []
    for p in get_payloads("sqli", category="error_based", depth=depth):
        extra.append({"value": p["payload"], "type": "sqli"})
    for p in get_payloads("lfi", category="linux", depth=depth):
        extra.append({"value": p["payload"], "type": "lfi", "key_signal": p.get("signature", "root:[x*]:0:0")})
    return self.PAYLOADS + extra
```

Dans `scan()`, remplacer l'appel à `_fuzz_endpoint` pour lui passer la liste calculée une fois : `payload_defs = self._build_payload_defs(context.get("depth"))`, puis `_fuzz_endpoint(ep, context, payload_defs)`. `_fuzz_endpoint` et sa boucle interne (`for payload_def in self.PAYLOADS:`) utilisent désormais le paramètre `payload_defs` reçu au lieu de `self.PAYLOADS`.

- [ ] **Step 4: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_modules.py::test_json_fuzzer_pulls_extra_sqli_and_lfi_payloads -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/json_fuzzer.py backend/tests/test_modules.py
git commit -m "feat(json-fuzzer): pull extra sqli/lfi payload variety from existing catalogs"
```

---

### Task 14: Enrichir `form_fuzzer.py` via les catalogues `sqli`/`lfi`

**Files:**
- Modify: `backend/scanner/modules/form_fuzzer.py` (constante `PAYLOADS` lignes 40-45 ; boucle lignes 101-141)
- Test: `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `get_payloads("sqli", category="error_based", depth=...)`, `get_payloads("lfi", category="linux", depth=...)` — même approche que Task 13.

- [ ] **Step 1: Écrire le test**

```python
def test_form_fuzzer_pulls_extra_sqli_and_lfi_payloads(mocker):
    from scanner.modules.form_fuzzer import FormFuzzerModule
    import scanner.modules.form_fuzzer as ff_mod

    spy = mocker.spy(ff_mod, "get_payloads")
    mocker.patch("scanner.core.http.post", return_value=mocker.Mock(text="ok"))
    mocker.patch("scanner.core.http.get", return_value=mocker.Mock(text="ok"))

    form = {"action": "http://a/submit", "method": "POST",
            "fields": [{"name": "comment", "type": "text", "value": ""}]}
    FormFuzzerModule().scan("http://a", {"crawled": {"forms": [form]}})
    families_called = {c.args[0] for c in spy.call_args_list if c.args}
    assert families_called >= {"sqli", "lfi"}
```

- [ ] **Step 2: Lancer le test, vérifier qu'il échoue**

Run: `pytest backend/tests/test_modules.py::test_form_fuzzer_pulls_extra_sqli_and_lfi_payloads -v`
Expected: FAIL

- [ ] **Step 3: Étendre `PAYLOADS` avec les variantes catalogue au lieu de le remplacer**

Importer `from scanner.payloads import get_payloads`. Même pattern que Task 13 :

```python
def _build_payload_defs(self, depth):
    extra = []
    for p in get_payloads("sqli", category="error_based", depth=depth):
        extra.append({"value": p["payload"], "type": "sqli", "signature_in_response": None, "expects_error": True})
    for p in get_payloads("lfi", category="linux", depth=depth):
        extra.append({"value": p["payload"], "type": "lfi", "signature_in_response": p.get("signature", "root:[x*]:0:0")})
    return self.PAYLOADS + extra
```

Dans `scan()` (qui appelle `_fuzz_form(form, context)` pour chaque form), calculer `payload_defs = self._build_payload_defs(context.get("depth"))` une fois, le passer à `_fuzz_form(form, context, payload_defs)`, puis à la boucle interne `for payload_def in self.PAYLOADS:` → `for payload_def in payload_defs:`.

- [ ] **Step 4: Lancer le test, vérifier qu'il passe**

Run: `pytest backend/tests/test_modules.py::test_form_fuzzer_pulls_extra_sqli_and_lfi_payloads -v`
Expected: PASS

- [ ] **Step 5: Lancer toute la suite backend pour vérifier la non-régression globale**

Run: `pytest backend/tests/ -v`
Expected: PASS (tous les tests, anciens et nouveaux)

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/modules/form_fuzzer.py backend/tests/test_modules.py
git commit -m "feat(form-fuzzer): pull extra sqli/lfi payload variety from existing catalogs"
```

---

## Self-Review (effectué par l'auteur du plan)

1. **Couverture spec :** §4.1 → Task 1 ; §4.2 → Tasks 2-5 ; §4.3 → Tasks 5 (partiel) + 7 ; §4.4 → Tasks 8-14 ; §4.5 → Task 6 ; §4.6 → tests intégrés à chaque tâche. Aucune section sans tâche.
2. **Granularité :** chaque step laisse exactement une chose raisonnable à écrire ; les corps de fonction donnés sont soit déjà déterminés par signature+test (filtrage cumulatif, Task 1), soit une transcription directe de valeurs existantes (Tasks 8-12) — pas de code "pour plus tard".
3. **Cohérence des types :** `get_payloads(family, category=None, depth=None)` utilisé identiquement dans toutes les tâches ; `context.get("depth")` partout, jamais une autre clé.
4. **Review Focus :** les 5 points sont chacun couverts par un test nommé dans une tâche précise (voir section Review Focus ci-dessus, chaque ligne référence sa tâche).
5. **Proportion :** 14 tâches pour une spec de ~150 lignes — comparable aux rounds précédents de ce projet (Round 8 : 7 tâches pour une spec plus courte, scope plus large ici car 9 modules touchés au total).
