# 🗺️ VulnScan — Roadmap

Le projet est livré en **rounds successifs** pour rester maintenable. Voici où nous en sommes et ce qui reste.

## ✅ Round 0 (initial)
- Extension MV3 fonctionnelle (popup, devtools panel, content-script, options)
- Backend Flask : `/health`, `/analysis/parse-html`, `/analysis/headers`, `/analysis/blind-sqli`
- Site de test JuiceCorp (~10 vulns)

## ✅ Round 1 (cette session)
- **UI : cartes pliables** avec "Voir plus", search, filtres par sévérité, progression temps réel, onglet Historique
- **Enrichissement du modèle** : chaque finding a OWASP, CWE, CVSS v3.1 (score + vecteur), impact, références
- **Architecture modulaire backend** : `scanner/core/` + `scanner/modules/` (headers, sqli, xss, info-disclosure)
- **Moteur** avec auto-découverte des modules et **fusion bayésienne** des signaux
- **Exports** : JSON, CSV, HTML, **PDF** (via impression), **XML** (nouveau)
- **WebLab** : projet PHP/MySQL pour WAMP — 8 pages vulnérables + admin panel + API + JWT + schéma MySQL + 5 users + 10 produits + commandes + factures

## ✅ Round 2 (cette session)
- **8 nouveaux modules backend** : LFI, SSRF, command-injection, open-redirect, IDOR, JWT analyzer (alg=none + dico HS256), CORS misconfig, XXE
- **Persistance SQLite** côté backend : `database/db.py` + table `scans` + table `findings` indexées + endpoints `/history/list`, `/history/save`, `/history/<id>`, `/history/diff`, `DELETE /history/<id>`
- **Comparaison de 2 scans** : onglet "⇆ Diff" avec sélection par checkboxes, calcul added/removed/changed/stable, cartes colorées (rouge = nouvelles régressions, vert = corrigées, jaune = modifiées)
- **WebLab étoffé** : `upload.php` (file upload sans validation), `ssrf.php` (proxy URL), `xxe.php` (parseur XML avec entités externes), `backup/database_2025.sql` (dump exposé), `api/orders.php` (IDOR + SQLi + leak SQL)
- **Tests unitaires pytest** : `tests/test_engine.py`, `tests/test_database.py`, `tests/test_modules.py` + `run_tests.bat` Windows

## ✅ Round 3 (cette session)
- **Sauvegarde auto SQLite** : tout scan terminé est poussé vers `/history/save` en best-effort
- **Endpoint `GET_RESULTS_BACKEND`** pour rapatrier l'historique persisté côté serveur
- **Catalogue de payloads JSON** : `scanner/payloads/{xss,sqli,lfi,ssrf,dir_bruteforce}.json` + loader `PayloadCatalog`
- **Moteur d'inférence contextuelle** (`scanner/core/inference.py`) avec 5 règles :
  - CSRF neutralisé par SameSite=Strict observé
  - X-Frame-Options redondant si CSP frame-ancestors présent
  - Lib obsolète XSS atténuée par CSP stricte
  - Multiples findings JWT consolidés si alg=none déjà critique
  - Consolidation des sensitive-data low en lot
- **4 nouveaux modules backend** :
  - `dir-bruteforce` : 30+ chemins (admin, VCS, configs, backups) avec rate-limit 5 req/s
  - `tech-fingerprint` : Apache/Nginx/PHP/WordPress/Drupal/React/Angular/jQuery via headers + HTML + cookies
  - `file-exposure` : .git/HEAD, .git/config, .env, swagger.json, phpinfo, .DS_Store avec signature de contenu
  - `rate-limit` : burst test sur endpoints sensibles (login, auth, api)
- **WebLab étoffé** :
  - `crlf.php` : CRLF injection sur header Set-Cookie
  - `sessions.php` : tokens prévisibles via `md5(time())`
  - `admin/delete_user.php` : action destructive en GET sans auth + CSRF + SQLi
  - `.git-exposed-demo/HEAD` + `.git-exposed-demo/config` : repo Git "leaké"

## ✅ Round 4 (cette session) — surface d'attaque étendue
- **Crawler intégré** (`scanner/core/crawler.py`) : extrait liens, formulaires (action/method/fields), endpoints API depuis JS (fetch/axios/XHR), robots.txt, sitemap.xml
- **Moteur enrichi** : phase 0 = découverte. Le contexte du scan contient désormais `crawled.{urls, forms, api_endpoints}` que tout module peut consommer
- **4 nouveaux modules d'injection sur surface étendue** :
  - **`form-fuzzer`** : POST sur chaque formulaire découvert, fuzz de chaque champ texte avec payloads XSS/SQLi/LFI. Filtre les forms dangereux (logout, delete, password)
  - **`header-injection`** : injecte dans User-Agent, Referer, X-Forwarded-For, Host, Cookie. Détecte XSS via panel admin, SQLi via logs, CRLF, Host Header Injection
  - **`param-discovery`** (Arjun-like) : wordlist de 200+ noms communs, détecte les params cachés via reflet de valeur sample ou diff de réponse
  - **`json-fuzzer`** : détecte endpoints API (`/api/`, `/v1/`, `/v2/`), envoie POST application/json avec payloads dans chaque clé. Détecte XSS, SQLi, NoSQLi (`{$gt: ""}`), LFI
- **2 nouveaux catalogues de payloads** : `headers.json` (UA/Referer/XFF/Host/Cookie) + `param_names.json` (~80 noms répartis en common/auth/feature_flags/ssrf/file/ecommerce)
- **Tests** : `test_crawler.py` (parsing form, extraction endpoints JS) + extension de `test_engine.py` aux 4 nouveaux modules

## ✅ Round 5 (cette session) — Pro-grade upgrades (5 game-changers)
- **🔑 Scan authentifié** : nouveau helper `scanner/core/http.py` qui injecte cookies/headers d'auth depuis le contexte. UI options étendue avec champs Cookies / Bearer / Header custom. Le crawler ET les modules utilisent l'auth.
- **📡 OOB Collaborator** : `routes/oob.py` (endpoint `/oob/log/<uuid>` + `/oob/check/<uuid>`) et helper `scanner/core/oob.py`. Le module SSRF utilise l'OOB pour confirmer les **blind SSRF** : si le canary est hit dans les 4s après envoi du payload, la vuln est CONFIRMÉE même sans retour visible. Confidence 100%, severity critical.
- **⏱ SQLi time-based** : module sqli enrichi avec `SLEEP(4)` / `pg_sleep(4)` / `WAITFOR DELAY '0:0:4'`. Mesure baseline + delta. Confirmation si Δ ≥ 3.5s. Couvre les blind SQLi que boolean-based rate.
- **🔐 SSL/TLS detail module** : analyse via stdlib `ssl` + `socket`. Détecte certif expiré, auto-signé, protocoles obsolètes (SSLv3, TLS 1.0, TLS 1.1), cipher suites faibles (RC4, DES, EXPORT, NULL, MD5).
- **🌐 GraphQL fuzzer** : détection endpoint (`/graphql`, `/api/graphql`, etc.), introspection activée, suggestions "Did you mean", batching DoS, SQLi via variables typées.

## ✅ Round 5 (suite — Option B) — 5 dernières features pro-grade
- **🛡 WAF Detection module** (`waf-detect`) + helper `scanner/core/waf.py` :
  - Identifie Cloudflare / Akamai / AWS WAF / Imperva / Sucuri / F5 / ModSecurity / Barracuda / Fortinet via signatures (headers, server, body)
  - Helper `mutate(payload)` qui génère 7+ variantes (case-mix, URL encoding simple/double, HTML entity, SQL comment injection, tab/newline, null byte) pour bypass simple
  - Met le WAF détecté dans `context["waf"]` pour usage par les autres modules
- **🏃 Race Conditions module** (`race-conditions`) :
  - Envoie 8 requêtes parallèles via `ThreadPoolExecutor` sur les forms POST découverts par le crawler
  - Détecte les TOCTOU (coupon stacking, double-spend, multi-vote) quand plus de 50% des req parallèles réussissent
  - Filtre les forms dangereux (logout, delete, password) pour ne pas casser la cible
- **🌐 Subdomain Enumeration module** (`subdomain-enum`) :
  - DNS bruteforce parallèle (20 threads) sur 70+ noms communs (api, dev, staging, admin, beta...)
  - Bonus : lookup Certificate Transparency via crt.sh (si internet)
- **🎚 Scan Profiles** : sélecteur Quick / Standard / Deep / OWASP-only / API / Custom dans Options.
  - Quick = passive uniquement (~5 s)
  - Standard = mix équilibré (15 modules)
  - Deep = TOUS les 25 modules
  - OWASP = focus Top 10
  - API = focus REST + GraphQL + JWT
  - Le service-worker mappe profile → liste de modules avant /scanner/run
- **🔗 Chain Detection rules** (4 nouvelles règles dans `inference.py`) :
  - **LFI + log poisoning** : severity escalade à critical (potentiel RCE)
  - **Open Redirect + XSS reflected** : severity escalade à high (phishing crédible)
  - **Subdomain enum + insecure cookie** : severity escalade à high (subdomain takeover)
  - **Missing SRI + Mixed Content** : severity escalade à high (MITM peut injecter JS via CDN)
  - Ces règles **élèvent** la sévérité (les autres l'atténuent) — vraie analyse de risque combiné

## 🟠 Round 6 (souhaitable)
- **Moteur d'inférence contextuelle** : règles qui valident automatiquement chaque finding (ex: une CSRF n'est pas exploitable si SameSite=Strict)
- **Catalogue de payloads** (`scanner/payloads/`) versionné, sélection dynamique selon contexte
- **Subdomain enum** + **technology fingerprinting** (WhatWeb/Wappalyzer-like) côté backend
- **Sitemap/robots.txt parsing** automatique
- **Directory bruteforce** avec wordlist
- **Rate-limiting** intelligent côté scanner pour ne pas tuer la cible

## 🔵 Round 5 (R&D)
- **Moteur de scoring "appris"** : ajustement bayésien du seuil de confiance par type, basé sur le feedback utilisateur ("vrai positif / faux positif" boutons dans l'UI)
- **Templates de rapports** personnalisables (Markdown → HTML/PDF)
- **Mode "compare scans"** : diff entre 2 scans avec mise en évidence des régressions
- **Mode multi-page crawl** (avec puppeteer côté backend)

## ⚠️ Hors-scope assumé
- **Pentest réseau / port scan** : nécessite des outils dédiés (nmap, masscan) — pas adapté à une extension navigateur
- **Vraie IA générative** : ne pas faire de promesses non tenables. On reste sur du règles + scoring bayésien, qui est suffisant et **explicable**
- **Exploitation post-auth automatisée** : risque légal trop élevé, on reste sur la détection

## Principes
- **Honnêteté** sur ce que le scanner peut et ne peut pas faire (false negatives, etc.)
- **Backend Python = requis** car il fait ce que le browser ne peut pas
- **WebLab strictement local** — jamais sur Internet
