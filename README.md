# 🛡️ VulnScan — Scanner de vulnérabilités web (extension Chrome + backend Python)

![VulnScan](docs/promo/banner.png)

![Démo VulnScan](docs/promo/demo.gif)

*(20s, silencieuse — [vidéo HD .mp4](docs/promo/demo.mp4))*

VulnScan analyse les pages web dans Chrome pour détecter des vulnérabilités du **OWASP Top 10** et au-delà. Il combine :
- une extension Chrome (Manifest V3) qui analyse le DOM côté client
- un backend Python Flask **requis** qui fait ce que le navigateur ne peut pas (vrais en-têtes HTTP, base CVE, corrélation bayésienne)
- un dashboard DevTools moderne avec cartes pliables, filtres, export multi-formats

Voir [ROADMAP.md](./ROADMAP.md) pour l'état d'avancement.

## Démarrage rapide

### 1. Backend Python (REQUIS)
```bash
cd backend
# Windows
start.bat
# Linux / macOS
./start.sh
```
Le backend écoute sur `http://127.0.0.1:9876`.

### 2. Extension Chrome
1. Ouvrir `chrome://extensions`
2. Activer le **mode développeur**
3. **Charger l'extension non empaquetée** → sélectionner le dossier `extension/`
4. Ouvrir n'importe quelle page → F12 → onglet **VulnScan** → **▶ Lancer un scan**

### 3. Site de test
Deux options selon ton OS :
- **JuiceCorp** (statique HTML, marche partout) — `test-site/` → `python -m http.server 8000`
- **WebLab** (PHP + MySQL, plus complet) — copier `WebLab/` dans `C:\wamp64\www\` et importer le SQL

## Architecture

```
vulnscan-windows/
├── extension/                ← Extension Chrome MV3
│   ├── manifest.json
│   └── src/
│       ├── background/       Service worker (orchestrateur)
│       ├── content/          Analyse passive du DOM
│       ├── devtools/         Dashboard (panel.html + panel.js)
│       ├── popup/            Popup rapide
│       ├── options/          Page de configuration
│       └── utils/            constants.js, taxonomy.js (OWASP/CWE/CVSS)
│
├── backend/                  ← Backend Python Flask (REQUIS)
│   ├── app.py                Point d'entrée
│   ├── start.bat/.sh         Lanceurs
│   ├── routes/               Routes HTTP
│   │   ├── health.py
│   │   ├── analysis.py       (parse-html, headers, blind-sqli legacy)
│   │   ├── augment.py        fetch-headers, cve-check, correlate
│   │   └── scanner_engine.py /scanner/modules, /scanner/run
│   └── scanner/              ← Moteur modulaire (Round 1+)
│       ├── core/
│       │   ├── engine.py     Auto-découverte + fusion bayésienne
│       │   └── module_base.py ScannerModule, Finding
│       └── modules/          ← Détecteurs
│           ├── headers.py
│           ├── sqli.py
│           ├── xss.py
│           └── info_disclosure.py
│
├── test-site/                Site statique (JuiceCorp)
├── WebLab/                   ← Lab PHP+MySQL (WAMP)
├── ALGORITHME.md             Comment marche le scoring bayésien
├── ROADMAP.md                Rounds suivants
└── README.md                 ← Vous êtes ici
```

## Pipeline de scan

```
1. User clic "▶ Scan"
       ↓
2. Service worker vérifie GET /health (sinon abandon avec erreur claire)
       ↓
3. Phase A — Content-script (browser)
   - 10 détecteurs DOM passifs (eval, innerHTML, jQuery old, CSRF, etc.)
   - Retourne findings + contexte (libs détectées, etc.)
       ↓
4. Phase B — Backend Python
   - POST /analysis/fetch-headers   ← vrais headers HTTP serveur
   - POST /analysis/cve-check       ← base CVE locale (jQuery/Angular/Lodash/Moment)
   - POST /analysis/correlate       ← scoring bayésien des signaux
   - Optionnel : POST /scanner/run  ← moteur modulaire (modules personnalisés)
       ↓
5. Service worker enrichit chaque finding via taxonomy.js (OWASP/CWE/CVSS)
       ↓
6. Diffusion VULN_FOUND → panel affiche en cartes pliables
       ↓
7. Export possible : JSON, CSV, HTML, XML, PDF (impression)
```

## Détecteurs disponibles (Round 1)

| Module | Côté | Type | Statut |
|---|---|---|---|
| `dangerous-patterns` | client | eval/document.write/innerHTML | ✅ |
| `dom-sinks` | client | href javascript:, iframe sandbox, etc. | ✅ |
| `vulnerable-libs` | client | jQuery, Angular, Lodash, Moment | ✅ |
| `csrf` | client | forms POST sans token | ✅ |
| `mixed-content` | client | HTTPS+HTTP | ✅ |
| `open-redirect` | client | params ?next= etc. | ✅ |
| `missing-sri` | client | CDN sans integrity | ✅ |
| `cookies` | client | document.cookie sans HttpOnly | ✅ |
| `clickjacking` | client | absence X-Frame-Options HTML | ✅ |
| `sensitive-data` | client | API keys, JWT, paths, emails | ✅ |
| `headers` | backend | vrais headers HTTP / qualité CSP | ✅ |
| `sqli` (error + blind boolean) | backend | injection SQL passive/semi-active | ✅ |
| `xss` (reflected via reflection marker) | backend | XSS réfléchi | ✅ |
| `info-disclosure` (BeautifulSoup) | backend | secrets, stack traces, etc. | ✅ |
| `lfi` | backend | path traversal + signatures /etc/passwd | ✅ |
| `ssrf` | backend | params URL-like, payloads loopback/file:// | ✅ |
| `command-injection` | backend | séparateurs shell sur params suspects | ✅ |
| `open-redirect` | backend | redirection 3xx vers canary externe | ✅ |
| `idor` | backend | id-walk heuristique sur params numériques | ✅ |
| `jwt-analysis` | backend | alg=none + dico HS256 + exp | ✅ |
| `cors-misconfig` | backend | origine réfléchie / `*` + credentials | ✅ |
| `xxe` | backend | DOCTYPE + ENTITY SYSTEM file:// | ✅ |
| `dir-bruteforce` | backend | wordlist + content signature (rate-limited 5 req/s) | ✅ |
| `tech-fingerprint` | backend | CMS, langage, server via headers+HTML+cookies | ✅ |
| `file-exposure` | backend | .git/HEAD, .env, swagger.json, phpinfo (signature contenu) | ✅ |
| `rate-limit` | backend | burst test sur login/auth/api | ✅ |
| `form-fuzzer` | backend | POST + body fuzzing sur forms découverts par le crawler | ✅ |
| `header-injection` | backend | injecte payloads dans User-Agent, Referer, XFF, Host, Cookie | ✅ |
| `param-discovery` | backend | wordlist Arjun-like de 80+ noms de params cachés | ✅ |
| `json-fuzzer` | backend | détection endpoints API + POST application/json avec payloads | ✅ |
| `ssl-tls` | backend | analyse TLS : protocoles obsolètes, ciphers faibles, certif expiré/auto-signé | ✅ |
| `graphql` | backend | introspection, batching DoS, SQLi via variables, suggestions activées | ✅ |
| **Bonus pro** | extension + backend | **Auth context** (cookies+JWT+Bearer) propagé à tous modules + crawler | ✅ |
| **Bonus pro** | backend | **OOB Collaborator** pour blind SSRF/XSS/XXE | ✅ |
| **Bonus pro** | backend | **SQLi time-based** (SLEEP/pg_sleep/WAITFOR DELAY) | ✅ |
| `waf-detect` | backend | identifie Cloudflare/Akamai/AWS WAF + helper de mutation pour bypass | ✅ |
| `race-conditions` | backend | TOCTOU via N requêtes parallèles sur forms POST | ✅ |
| `subdomain-enum` | backend | DNS bruteforce + crt.sh Certificate Transparency | ✅ |
| **Scan profiles** | extension | Quick / Standard / Deep / OWASP / API / Custom | ✅ |
| **Chain detection** | inference | 4 règles d'élévation : LFI+log, OR+XSS, sub+cookie, SRI+mixed | ✅ |

## Tester

1. Démarrer le backend : `backend/start.bat`
2. Démarrer un site vulnérable : `python -m http.server 8000` dans `test-site/`, ou copier `WebLab/` dans WAMP
3. Charger l'extension dans Chrome
4. Aller sur le site, F12 → VulnScan → Lancer un scan
5. Tu devrais voir 20-40 vulnérabilités selon la page, chacune avec son score CVSS, CWE, OWASP, et un panneau pliable contenant tout le détail

## Export multi-format

Bouton dans la status bar :
- **JSON** : format complet, parsable, conserve tous les champs
- **XML** : conforme, avec CDATA pour les preuves
- **CSV** : pour import Excel (BOM UTF-8)
- **HTML** : rapport stylé avec résumé exécutif et KPIs
- **PDF** : ouvre l'HTML en mode impression, Ctrl+P → Enregistrer en PDF

## ⚠️ Sécurité & éthique

- **Le mode "actif"** (SQLi blind, XSS reflection) envoie des requêtes vers la cible. À utiliser uniquement sur **vos propres sites** ou avec autorisation écrite.
- **WebLab** ne doit jamais être exposé sur Internet.
- VulnScan n'exploite jamais une vulnérabilité — il la détecte et fournit la recommandation OWASP.
