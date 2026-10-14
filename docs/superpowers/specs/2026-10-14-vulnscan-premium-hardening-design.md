# VulnScan — Durcissement "premium" (moteur, UI, rapports)

**Date :** 2026-10-14
**Statut :** En revue
**Auteur :** Claude (session interactive avec Chris Nahum)

## 1. Contexte

VulnScan est une extension Chrome MV3 + backend Python Flask qui scanne des
pages web pour des vulnérabilités OWASP Top 10 et au-delà. Le moteur
(`backend/scanner/`) compte déjà 30+ modules (SQLi, XSS, LFI, SSRF, XXE, JWT,
CORS, WAF detection, race conditions, subdomain enum...), un crawler, un
système d'inférence contextuelle (atténuation/élévation de sévérité), un
scoring bayésien multi-signaux, une persistance SQLite avec diff de scans, et
un dashboard DevTools (`panel.html`/`panel.js`) à cartes pliables avec KPIs,
donut de répartition et export multi-format (JSON/CSV/HTML/PDF/XML).

**Cadre d'usage, inchangé :** scanner défensif pour cibles qu'on possède ou
qu'on est autorisé à tester (README.md §Sécurité & éthique). Cette spec ne
change pas ce cadre — elle ne fait que renforcer la détection, l'UI et les
rapports.

### Objectif

Faire monter VulnScan au niveau des fonctionnalités "signature" des outils de
référence du marché pour ce périmètre — **Burp Suite Professional**, **Nuclei**,
**Caido** — sur trois axes validés avec l'utilisateur :

- **(A) Précision du moteur** — confirmation et preuve, pas seulement heuristique
- **(B) UI/UX** — visibilité sur ce qui a été testé, façon Caido
- **(C) Qualité des rapports** — preuve rejouable, formats pro (SARIF)

### Non-objectifs (YAGNI explicite)

- Pas de réécriture du panel en framework (React/Vue) — JS/CSS vanilla conservé
- Pas de scoring "appris"/ML — on reste sur des règles déclaratives inspectables
  (cohérent avec `ALGORITHME.md` qui refuse déjà le marketing "IA"/"quantique")
- Pas de PDF natif (dépendance headless Chrome) — on garde l'impression navigateur
- Pas de capacités de command-and-control, d'implant ou de post-exploitation —
  hors cadre pour un scanner de détection, quel que soit l'axe de comparaison
- Pas de nouveau framework de test pour l'extension (reste vanilla + vérif manuelle)

### Décomposition en rounds

Pour rester livrable à chaque étape (continuité avec `ROADMAP.md`) :

| Round | Contenu | Dépend de |
|---|---|---|
| **Round 6** | Moteur : matchers déclaratifs, capture requête/réponse, triage, SSTI, NoSQLi, rate-limiter global | — |
| **Round 7** | UI : trafic, surface d'attaque, console d'activité, triage UI, sélecteur de modules, thème clair | Round 6 (capture req/resp) |
| **Round 8** | Rapports : preuve embarquée, SARIF, résumé data-driven, snippets de remédiation, tendance | Round 6 + 7 |

---

## 2. Round 6 — Moteur de détection

### 2.1 Moteur de matchers déclaratif

**Problème :** chaque module réimplémente sa propre logique de confirmation en
Python (ex. `sqli.py` compare des ratios Levenshtein inline). Pas de format
commun, pas de réutilisation, difficile d'auditer "pourquoi ce finding est-il
confirmé ?".

**Solution :** `backend/scanner/core/matchers.py` — un petit moteur de
matchers inspiré de Nuclei, consommé optionnellement par les modules :

```python
# Un "matcher" évalue une HttpResult (status, headers, body, elapsed_ms)
# contre une condition déclarative.
@dataclass
class HttpResult:
    status: int
    headers: dict
    body: str
    elapsed_ms: float

@dataclass
class Matcher:
    type: str              # "status" | "word" | "regex" | "time"
    part: str = "body"      # "body" | "header" | "status"
    words: list[str] = field(default_factory=list)
    regex: str | None = None
    status_codes: list[int] = field(default_factory=list)
    min_delay_ms: float | None = None
    negative: bool = False  # inverse le résultat (ex: absence de pattern)

def evaluate(matchers: list[Matcher], condition: str, result: HttpResult) -> bool:
    """condition = 'and' | 'or'"""
```

Les fichiers `scanner/payloads/*.json` gagnent un champ optionnel `matchers`
par entrée de payload (rétro-compatible — les entrées sans `matchers` gardent
le comportement actuel du module) :

```json
{
  "payload": "' OR '1'='1",
  "description": "Classic SQLi boolean bypass",
  "confidence_hint": 85,
  "matchers": [
    {"type": "word", "part": "body", "words": ["SQL syntax", "mysql_fetch"]},
    {"type": "status", "status_codes": [500]}
  ],
  "matchers_condition": "or"
}
```

**Portée Round 6 :** le moteur + migration de 2 modules pilotes (`sqli`,
`xss`) vers le format matchers pour valider l'approche, sans casser les 28
autres (qui continuent avec leur logique actuelle). Les rounds suivants
pourront migrer le reste progressivement — pas dans cette spec (YAGNI : on ne
migre pas ce qui marche déjà sans preuve que ça aide).

### 2.2 Capture requête/réponse (preuve rejouable)

**Problème :** `Finding.evidence` est un texte libre (ex. `"sim(base, true)=0.91"`).
Aucun outil pro ne s'arrête là — Burp et Caido attachent la requête/réponse
brute à chaque issue, ce qui permet de la rejouer et de la vérifier.

**Solution :** extension de `Finding` (`module_base.py`) avec deux champs
optionnels :

```python
evidence_request: Optional[Dict[str, Any]] = None   # {method, url, headers, body}
evidence_response: Optional[Dict[str, Any]] = None  # {status, headers, body_snippet, elapsed_ms}
```

- `body_snippet` tronqué à 4 Ko (pas de réponses complètes énormes en mémoire/DB)
- Les headers d'auth (`Authorization`, `Cookie`) sont **redactés** (`***`) avant
  stockage — jamais de secret en clair dans un export partageable
- `scanner/core/http.py::send()` gagne un paramètre `capture: bool = False` qui,
  si activé, retourne `(response, evidence_request, evidence_response)` —
  les modules actifs (sqli, xss, lfi, ssrf, xxe, command-injection, idor,
  open-redirect) l'activent sur leur requête de confirmation finale
  uniquement (pas sur chaque requête de sondage, pour limiter le volume)
- `Finding.to_dict()` sérialise les deux champs sous `evidenceRequest`/`evidenceResponse`
  (camelCase, cohérent avec le reste du contrat JSON existant)

### 2.3 Triage persistant (confirmé / faux positif)

**Problème :** aucune mémoire des décisions de l'utilisateur — chaque scan
reparaît avec les mêmes faux positifs à re-trier mentalement.

**Solution :**
- Colonne `triage_status` (`"unreviewed"|"confirmed"|"false_positive"`, défaut
  `"unreviewed"`) et `triage_note` (texte libre) sur la table `findings`
  (migration additive `ALTER TABLE` dans `database/db.py::init_db()`, pas de
  rupture du schéma existant)
- Nouvel endpoint `PATCH /history/triage/<finding_id>` body `{status, note?}`
  dans `routes/history.py`
- Pas de ré-apprentissage automatique du scoring — le triage est une donnée
  d'affichage/filtrage, pas une entrée du moteur bayésien (reste honnête et
  explicable, cf. non-objectifs)

### 2.4 Combler 2 trous de couverture confirmés

Vérifiés dans le code pendant l'exploration — pas des suppositions :

- **SSTI** — `constants.js` expose `testSSTI: false` dans `DEFAULT_CONFIG`
  depuis le début, mais **aucun module `ssti` n'existe** et le flag n'est
  jamais lu côté backend. Nouveau module `scanner/modules/ssti.py` :
  payloads `{{7*7}}` (Jinja2/Twig), `${7*7}` (Freemarker/Velocity),
  `#{7*7}` (Thymeleaf) injectés sur les paramètres découverts par le crawler,
  confirmation par réflexion du résultat calculé (`49`) dans la réponse.
- **NoSQL injection** — `json-fuzzer` mentionne `{$gt: ""}` dans sa docstring
  mais ne l'implémente pas réellement comme classe de vuln distincte (vérifié
  dans le code : pas de détection spécifique aux opérateurs Mongo). Nouveau
  module `scanner/modules/nosqli.py` : payloads `{"$gt": ""}`,
  `{"$ne": null}`, `';return true;//` sur les endpoints JSON découverts,
  détection par comparaison de comportement (auth bypass / retour de données
  supplémentaires vs baseline).
- **Rate-limiter global** — `requestsPerSecond` existe dans `DEFAULT_CONFIG`
  et dans Options UI mais n'est lu par aucun module backend (seul
  `dir_bruteforce` a son propre throttle codé en dur à 5 req/s). Ajout d'un
  limiteur simple par host dans `scanner/core/http.py` (token bucket en
  mémoire, partagé via le `context` du scan), lu depuis
  `context["rate_limit_per_sec"]` transmis par le service-worker depuis la
  config utilisateur. Objectif : respecter la cible même en profil "Deep"
  — pas une feature de contournement, une feature de politesse/sécurité.

### 2.5 Tests (Round 6)

`backend/tests/` suit le pattern pytest existant :
- `test_matchers.py` — évaluation AND/OR, chaque type de matcher, négation
- `test_evidence_capture.py` — redaction des headers d'auth, troncature
- `test_triage.py` — migration de schéma idempotente, endpoint PATCH
- `test_ssti.py`, `test_nosqli.py` — détection sur payloads connus (fixtures
  Flask locales, pas de requêtes externes — cohérent avec `test_modules.py`)
- `test_rate_limiter.py` — respect du budget req/s sur une rafale simulée

---

## 3. Round 7 — UI/UX (`panel.html` / `panel.js`)

Dépend du Round 6 pour les données de capture requête/réponse et de triage.
Le dashboard actuel (cartes pliables, KPI, donut, diff) est conservé —
on ajoute des vues, pas une refonte.

### 3.1 Onglet "🌐 Trafic"

Nouvel onglet dans la barre `.tabs` existante. Liste toutes les
requêtes/réponses capturées (Round 6 §2.2) pendant le scan courant, triable
par statut/méthode/finding lié. Clic sur une ligne → vue 2 colonnes
(requête brute à gauche, réponse brute à droite, monospace, même style que
`.evidence` existant). C'est la fonctionnalité qui manque le plus
visiblement par rapport à Caido/Burp aujourd'hui.

### 3.2 Onglet "🗺 Surface"

Le crawler (`scanner/core/crawler.py`) calcule déjà `urls`, `forms`,
`api_endpoints` mais `routes/scanner_engine.py` ne renvoie que les 20
premiers/10 premiers dans `discovery` et le panel ne les affiche pas du tout
aujourd'hui. Nouvel onglet : liste groupée (Pages / Formulaires / Endpoints
API) avec, pour chaque nœud, le nombre de findings détectés sur cette URL
(jointure simple côté client sur `v.url`). Donne enfin une vue de couverture.

### 3.3 Console d'activité temps réel

Remplace la ligne unique `scanProgressLabel` par un flux empilé (dernier en
haut, max 50 lignes) : `"✓ sqli — 3 findings (2.1s)"`, `"… xxe en cours"`.
Le service-worker doit émettre un message `MODULE_PROGRESS` par module
(actuellement `/scanner/run` est un appel bloquant unique côté backend — pour
Round 7 on garde l'appel bloquant mais le backend logge déjà par module dans
`engine.py::run()` ; on expose cette granularité via un paramètre `stream`
optionnel sur `/scanner/run` qui renvoie du NDJSON incrémental au lieu d'un
seul JSON final. Fallback : si `stream` non supporté, le panel affiche juste
le flux "fin de scan" en un bloc — pas de régression.

### 3.4 Triage sur les cartes

Deux boutons sur chaque carte (`card-section` dédiée) : "✓ Confirmé" /
"✕ Faux positif", appelant `PATCH /history/triage/<id>` (Round 6 §2.3). Chip
de filtre supplémentaire "Faux positifs" dans `.chips`. Carte en statut
`false_positive` : style atténué (`opacity: 0.5`, bordure grise), exclue par
défaut des exports (option "Inclure les faux positifs" dans la boîte de
dialogue d'export).

### 3.5 Sélecteur de modules dans le panel

Aujourd'hui le profil "Custom" n'expose que 5 cases dans la page Options
séparée (`options.html`) alors que le moteur a 30 modules
(`GET /scanner/modules` renvoie déjà les métadonnées de tous). Nouvel onglet
"⚙ Modules" : les 30 modules groupés par `category` (celle déjà présente dans
`ScannerModule.category`), case à cocher par module, persisté dans
`chrome.storage.local` au même endroit que le reste de la config.

### 3.6 Thème clair

Actuellement 100% sombre. Ajout d'une variante claire des tokens CSS
`:root` existants + bouton bascule dans la topbar, persisté dans
`chrome.storage.local`. Pas de refonte des couleurs sémantiques
(critical/high/medium/low/info restent les mêmes teintes, juste les fonds/textes
qui s'inversent) — cohérent avec le système de variables déjà en place dans
`panel.html`.

### 3.7 Tests (Round 7)

Pas de framework de test introduit pour l'extension (vanilla JS sans build
de test aujourd'hui). Vérification manuelle via Chrome réel (chargement non
empaqueté) sur `test-site/` et `WebLab/`, suivant le processus déjà documenté
dans `README.md` §Tester. Pas de preview via navigateur intégré possible ici
(nécessite `chrome://extensions` + mode développeur, hors cadre d'un aperçu
web standard).

---

## 4. Round 8 — Rapports

Dépend des Rounds 6 (preuve) et 7 (triage) pour les données enrichies.

### 4.1 Preuve requête/réponse dans les exports

`evidenceRequest`/`evidenceResponse` (Round 6) ajoutés aux exports JSON
(déjà automatique, c'est le même objet), XML (`buildXML` — nouvelle balise
`<evidence-request>`/`<evidence-response>` avec CDATA), et HTML (`buildHTMLReport`
— nouvelle colonne/section dépliable par finding).

### 4.2 Export SARIF 2.1.0

Nouveau format dans `exportReport()` (`panel.js`) : `buildSARIF(scan)` génère
un document [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/) —
`runs[].results[]` avec `ruleId` (= `type`), `level` (mappé depuis severity),
`message.text` (= description), `locations[].physicalLocation.artifactLocation.uri`
(= url). C'est le format consommé par GitHub Code Scanning et la plupart des
pipelines CI — l'artefact "pro" le plus visible manquant aujourd'hui vs
Burp/Nuclei/Semgrep. Nouveau bouton `⬇ SARIF` dans la status bar.

### 4.3 Résumé exécutif data-driven

`buildHTMLReport()` a aujourd'hui un paragraphe fixe (mêmes phrases à chaque
rapport, seuls les chiffres changent). Remplacé par un texte généré à partir
des findings réels : top 3 catégories OWASP par contribution au score de
risque, et — si un scan précédent existe pour la même URL en historique —
comparaison ("+2 critiques depuis le dernier scan du 12/10").

### 4.4 Snippets de remédiation

`taxonomy.js` : chaque entrée gagne un champ optionnel `remediationSnippet`
(exemple de code court, ex. requête paramétrée pour `sqli`, en-tête CSP
pour `missing-header`). Affiché dans la carte (nouvelle section) et dans les
exports HTML/SARIF (`results[].fixes` en SARIF). Couvre d'abord les types à
fort volume : `sqli`, `xss`, `missing-header`, `insecure-cookie`,
`outdated-library` — pas les 30 types d'un coup (YAGNI, on complète au besoin).

### 4.5 Mini-graphe de tendance

La table `scans` (SQLite) a déjà `score` et `started_at` par URL. Nouvelle
requête `database/db.py::risk_trend(url, limit=10)` → liste de
`(started_at, score)`. Affiché comme sparkline SVG inline (même technique que
le donut existant — pas de dépendance charting) dans l'onglet Historique et
dans l'en-tête du rapport HTML exporté.

### 4.6 PDF

Pas de changement d'approche (impression navigateur conservée — non-objectif
§1). Amélioration du CSS d'impression existant (`@media print`) : répétition
de l'en-tête par page, évite la coupure d'une carte de finding entre deux
pages (`page-break-inside: avoid`).

### 4.7 Tests (Round 8)

- `test_sarif.py` — validité structurelle du document généré (schéma SARIF minimal)
- `test_risk_trend.py` — requête SQL sur fixtures de scans historiques
- Vérification manuelle du rendu HTML/PDF (pas d'automatisation visuelle introduite)

---

## 5. Risques et mitigations

| Risque | Mitigation |
|---|---|
| Capture req/resp alourdit le volume de données stockées | Troncature 4 Ko, uniquement sur requête de confirmation finale (pas chaque sondage) |
| Redaction d'auth insuffisante → fuite de secret dans un export partagé | Liste explicite de headers sensibles redactés avant toute sérialisation, testée (`test_evidence_capture.py`) |
| Migration SQLite additive casse l'historique existant | `ALTER TABLE ... ADD COLUMN` avec défaut, jamais de `DROP`/`RENAME` |
| Nouveaux modules (SSTI/NoSQLi) génèrent des faux positifs | Confirmation stricte (réflexion du calcul pour SSTI, diff comportemental pour NoSQLi), pas de détection sur simple présence de payload |
| Rate-limiter mal calibré ralentit excessivement le profil Deep | Défaut = valeur actuelle de `requestsPerSecond` (10), configurable, pas de régression de vitesse par défaut |
| Streaming NDJSON (§3.3) complexifie `/scanner/run` | Fallback explicite sans streaming — aucune régression si non supporté |

## 6. Hors-scope assumé (rappel)

Identique à `ROADMAP.md` §Hors-scope : pas de pentest réseau/port scan, pas
de promesse IA générative non tenable, pas d'exploitation post-auth
automatisée. Cette spec ajoute : pas de capacités de command-and-control ou
d'implant, sous aucune justification — un scanner de détection n'en a pas
besoin.
