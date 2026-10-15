# VulnScan — Profondeur de détection (catalogue de payloads)

**Date :** 2026-10-15
**Statut :** En revue
**Auteur :** Claude (session interactive avec Chris Nahum)

## 1. Contexte

Suite à `2026-10-14-vulnscan-premium-hardening-design.md` (moteur/UI/rapports,
Rounds 6-8, mergés), le retour utilisateur est que l'outil n'est "pas assez
puissant" pour rivaliser avec les références du marché (Burp Suite Pro,
Nuclei, Caido). Deux causes possibles ont été distinguées : l'outillage de
test manuel (proxy, Repeater, Intruder — explicitement **reporté**, "le
moteur on le fera un de ces quatre") et la **profondeur de détection**
(richesse/variété des payloads et signatures) — c'est cette seconde cause qui
fait l'objet de cette spec.

**Constat :** `backend/scanner/payloads/` contient déjà un loader propre
(`catalog.py` — `get_payloads(family, category)`) et des fichiers JSON
(`sqli.json`, `xss.json`, `lfi.json`, `ssrf.json`, `dir_bruteforce.json`,
`param_names.json`, `headers.json`) issus des Rounds 3-4. Mais **seuls 2
modules sur 29** (`dir_bruteforce.py`, `param_discovery.py`) les consomment
réellement — `sqli.py`, `xss.py`, `lfi.py`, `ssrf.py` ont chacun leur propre
liste de payloads **codée en dur**, dupliquée (en moins complète) du JSON qui
porte déjà leur nom. `headers.json` lui-même correspond en fait aux payloads
de `header_injection.py`, pas de `headers.py` — nommage historique à corriger
en passant.

Cadre d'usage inchangé (README.md §Sécurité & éthique) : mode actif réservé
aux cibles possédées/autorisées.

## 2. Objectif

Augmenter la richesse et la variété des payloads réellement envoyés par les
modules actifs, sans toucher à leur logique de détection/confirmation
(matchers, diff Levenshtein, OOB canary — déjà solides, cf. Round 6). Trois
étapes, dans cet ordre validé avec l'utilisateur :

1. Brancher `sqli.py`/`xss.py`/`lfi.py`/`ssrf.py` sur leur catalogue JSON
   existant (actuellement non utilisé).
2. Enrichir le contenu de ces catalogues (recherche de payloads publics
   reconnus : OWASP Testing Guide, PayloadsAllTheThings, SecLists).
3. Étendre le pattern catalogue aux autres modules réellement pilotés par
   payloads.

Chaque payload est étiqueté par **palier de profondeur** (`basic` /
`extended` / `aggressive`), propre au backend et découplé des 5 noms de
profils de l'extension (quick/standard/deep/owasp/api) — un profil se
contente de choisir un palier.

## 3. Non-objectifs (YAGNI explicite)

- Pas de fingerprinting CVE/version précis (ex: "Apache 2.4.49 → CVE-2021-41773")
  — portée d'une spec future et séparée.
- Pas de nouvelle abstraction "moteur de test générique" partagé entre
  modules — chaque module garde sa propre logique de confirmation ; seule la
  **source** des payloads change (le JSON au lieu de la constante Python).
- Pas de tag `depth` sur `dir_bruteforce.json`/`param_names.json` — ce sont
  des wordlists de découverte, pas des payloads d'attaque ; le concept de
  palier s'y applique mal.
- Pas de nouveau champ au niveau du body HTTP `/scanner/run` — `context` y
  est déjà transmis tel quel au moteur (`routes/scanner_engine.py:69-70`,
  `context = data.get("context", {})`) ; `depth` est juste une clé de plus
  dans l'objet `context` que l'extension construit déjà
  (`service-worker.js:370`). Zéro changement de route backend.

## 4. Conception

### 4.1 Schéma du catalogue — tag de profondeur

Champ optionnel `"depth"` sur chaque entrée des fichiers
`payloads/{sqli,xss,lfi,ssrf}.json` (et des futurs fichiers de l'étape 3) :
`"basic" | "extended" | "aggressive"`. Modèle **cumulatif** — palier
X renvoie tous les payloads de palier ≤ X. Une entrée sans `depth` vaut
`basic` (rétrocompatible : les payloads déjà en prod sont les plus éprouvés).

`backend/scanner/payloads/catalog.py` — `get_payloads(family, category=None,
depth=None)` :
- `depth=None` (défaut) → comportement actuel inchangé, tout est renvoyé.
  `dir_bruteforce.py`/`param_discovery.py` n'appellent jamais avec `depth` et
  ne changent donc pas.
- `depth="basic"|"extended"|"aggressive"` → filtre cumulatif sur le champ
  `depth` de chaque entrée (absent = `basic`).

### 4.2 Branchement des 4 modules (étape 1)

Le payload JSON remplace la constante Python ; la boucle de détection ne
change pas. Mapping confirmé par lecture du code actuel :

| Module | Constante remplacée | Catégories JSON consommées | Champs déjà alignés |
|---|---|---|---|
| `sqli.py` | `TIME_PAYLOADS` (4 tuples) | `time_based` | `dbms` déjà présent dans `sqli.json` |
| `sqli.py` (bonus) | test booléen inline (`AND 1=1--`/`AND 1=2--`) | `boolean_blind` | `expects` déjà présent — plus de variantes gratuitement |
| `lfi.py` | `PAYLOADS` (6 tuples) | `linux`+`windows`+`php_wrappers` (flatten) | `signature` ↔ champ JSON identique ; catégorie = `os_label` |
| `ssrf.py` | `PAYLOADS` (5 tuples) | `loopback`+`metadata`+`schemes` (flatten) | `description` ↔ champ JSON identique |
| `xss.py` | `PAYLOAD_CATALOG` (dict par contexte) | `html_context`/`attribute_context`/`js_context`/`url_context` | à réconcilier (4.3) : code utilise aussi `svg_context`/`img_context` absents du JSON ; JSON a `polyglot` inutilisé |

Chaque module appelle `get_payloads(<family>, category=..., depth=context.get("depth"))`
au début de `scan()` au lieu de lire sa constante de classe.

### 4.3 Enrichissement du contenu (étape 2)

Pour chaque catalogue touché par 4.2 :
- Réconcilier `xss.json` avec les contextes réellement utilisés par `xss.py`
  (ajouter `svg_context`/`img_context`, décider du sort de `polyglot` —
  probablement une 5e catégorie branchée en complément, pas supprimée).
- Enrichir chaque catégorie avec des payloads supplémentaires sourcés depuis
  des références publiques reconnues (OWASP Testing Guide,
  PayloadsAllTheThings, SecLists), avec attribution/`description` cohérente
  avec le style existant du JSON — pas de copie verbatim de contenu
  propriétaire, uniquement des payloads techniques génériques déjà
  largement publiés.
- Étiqueter chaque entrée nouvelle et existante avec `depth` : les payloads
  rapides/silencieux (erreurs, loopback simple) → `basic` ; les variantes
  plus nombreuses ou légèrement intrusives → `extended` ; le time-based et
  les schémas exotiques (gopher, dict, metadata cloud) → `aggressive`.
- Renommer/déplacer `headers.json` → son vrai propriétaire conceptuel est
  `header_injection.py` (confirmé par lecture : ce module construit déjà ses
  payloads inline, `headers.json` dupliquait sans être branché) ; ce
  renommage fait partie de l'étape 3 (4.4), pas de l'étape 1/2.

### 4.4 Extension aux autres modules (étape 3)

Modules identifiés comme réellement pilotés par une liste statique de
payloads (confirmé par lecture du code — constante `PROBES`/`PAYLOADS`/dict
de payloads présente) :

- `command_injection.py`, `ssti.py` (`PROBES`), `nosqli.py`, `xxe.py`,
  `header_injection.py` (dict inline → `headers.json` renommé/adapté),
  `json_fuzzer.py`, `form_fuzzer.py`.

Non retenus pour cette étape (vérifié par lecture, pas une simple
supposition) :
- `open_redirect.py` : pas de liste de payloads statique — construit un
  canary dynamique, pattern proche de SSRF/OOB plutôt qu'un catalogue.
- `graphql.py` : payloads = requêtes GraphQL structurées (introspection,
  batching), pas des chaînes plates — nécessiterait un schéma JSON différent
  (objets, pas strings) ; candidat pour une itération séparée si besoin.
- Modules non pilotés par payload (`headers.py`, `info_disclosure.py`,
  `tech_fingerprint.py`, `rate_limit.py`, `waf_detect.py`, `ssl_tls.py`,
  `cors_misconfig.py`, `race_conditions.py`, `idor.py`,
  `subdomain_enum.py`) : hors périmètre, confirmé en 4.1 de la conversation
  de brainstorming.

La liste exacte sera reconfirmée au moment de planifier l'étape 3 (lecture
fraîche de chaque module avant d'écrire les tâches) — ce n'est pas un
engagement figé de cette spec.

### 4.5 Plomberie `depth` (extension → backend)

Aucune nouvelle route ni nouveau champ de premier niveau. Dans
`service-worker.js`, à côté de `SCAN_PROFILES` (ligne ~307) :

```js
const DEPTH_FOR_PROFILE = {
  quick: "basic", standard: "extended", deep: "aggressive",
  owasp: "aggressive", api: "extended",
};
```

Dans `runActiveModules(cfg, url)` (ligne ~370), ajout d'une clé dans l'objet
`context` déjà construit :

```js
context: {
  ...(auth ? { auth } : {}),
  rate_limit_per_sec: cfg.requestsPerSecond,
  depth: DEPTH_FOR_PROFILE[cfg.scanProfile] || "extended",
},
```

Mapping justifié par la définition réelle de `SCAN_PROFILES`
(`service-worker.js:272-307`) : `quick` ne active aucun module à payload
(seulement passif) donc le palier ne s'y applique pas en pratique ; `deep`
est "TOUS les modules — exhaustif" → `aggressive` ; `owasp` vise la
couverture Top 10 → `aggressive` ; `standard`/`api` restent le défaut
équilibré → `extended`. Le profil `custom` n'a pas d'entrée dans
`DEPTH_FOR_PROFILE` → retombe sur `"extended"` via le `|| "extended"`.

Backend : chaque module lit `context.get("depth")` — `None` si absent
(ancien appelant/API directe) → aucun filtrage, comportement actuel
préservé.

### 4.6 Tests

- `catalog.py` : test unitaire du filtrage cumulatif de `get_payloads`
  (`depth="basic"` exclut `extended`/`aggressive` ; `depth=None` renvoie
  tout ; entrée sans champ `depth` traitée comme `basic`).
- Par module touché en 4.2/4.4 : un test qui vérifie que le module consomme
  bien le catalogue (mock ou fixture JSON minimal) et respecte le filtrage
  par `depth` passé dans `context`.
- Extension : test unitaire de `DEPTH_FOR_PROFILE` (chaque profil connu a un
  palier ; profil inconnu/`custom` → `"extended"`).

## 5. Risques / points d'attention

- Le filtrage par `depth` ne doit jamais **réduire silencieusement** la
  détection pour un appelant qui ne connaît pas ce paramètre (API directe,
  tests existants) — garanti par le défaut `depth=None` → pas de filtrage
  (4.1).
- L'enrichissement de contenu (4.3) doit rester des payloads techniques
  génériques déjà publics (pas de contenu propriétaire d'un outil commercial
  copié verbatim).
- `xss.json` a aujourd'hui une incohérence avec `xss.py` (catégories qui ne
  correspondent pas) — à corriger explicitement en 4.3, pas en silence.
