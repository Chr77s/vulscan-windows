# 🐍 VulnScan — Backend Python (Flask) — **REQUIS**

> ⚠️ **Depuis la v1.1, ce backend est obligatoire.** L'extension refusera de lancer un scan tant que le backend ne répond pas. Il fournit des analyses **impossibles à faire côté navigateur seul** : lecture des vrais en-têtes HTTP, base CVE, et corrélation bayésienne des signaux.

## Ce que fait le backend (et pourquoi il faut le lancer)

| Capacité | Pourquoi pas côté navigateur ? |
|---|---|
| Lire les **vrais en-têtes HTTP de réponse** (CSP, HSTS, X-Frame-Options, Set-Cookie…) | Un content-script Chrome ne voit que le DOM rendu, pas la réponse HTTP brute. Le backend fait un fetch côté serveur. |
| Vérifier les libs JS contre une **base CVE** (jQuery, Angular, Lodash, Moment, Bootstrap, Vue) | La base CVE serait trop lourde à embarquer dans l'extension. |
| **Corrélation bayésienne** des signaux multi-source : `confidence = 1 - Π(1 − cᵢ)` | Quand plusieurs détecteurs convergent (ex: CSP manquant + cookies non-HttpOnly + jQuery old) le risque réel monte. Le backend recombine ça proprement. |
| Détecter `unsafe-inline`/`unsafe-eval` dans une **CSP réelle**, et un en-tête `Server: nginx/1.18` qui fuit la version | Encore une fois, ces données vivent dans les vrais headers HTTP. |



## ⚡ Démarrage rapide

### Windows
Double-cliquez sur **`start.bat`** dans ce dossier.
Cela crée automatiquement un environnement virtuel `.venv`, installe les dépendances et lance le serveur sur `http://127.0.0.1:9876`.

### Linux / macOS
```bash
cd backend
chmod +x start.sh
./start.sh
```

### Démarrage manuel (si les scripts ne marchent pas)
```bash
cd backend
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

## ✅ Vérifier que ça tourne

Une fois lancé, vous devriez voir :
```
[VulnScan] VulnScan Backend Python demarre
[VulnScan] Ecoute sur http://127.0.0.1:9876
```

Test rapide depuis un autre terminal :
```bash
curl http://127.0.0.1:9876/health
# → {"status":"ok","version":"1.0.0"}
```

## 🔗 Activer le backend dans l'extension

1. Ouvrir l'icône **VulnScan** dans Chrome → bouton **⚙ Options**.
2. Dans la section **Backend Python (optionnel)** :
   - Cocher **Utiliser le backend Python**
   - Vérifier l'URL : `http://localhost:9876`
   - Cliquer sur **Tester maintenant** — le voyant doit passer au vert ✅
3. Cliquer sur **💾 Sauvegarder**.

Désormais l'extension délègue l'analyse fine des en-têtes HTTP au backend Python.

## 📡 Routes exposées

| Route | Méthode | Description |
|---|---|---|
| `/health` | GET | Ping santé (renvoie version + liste des endpoints) |
| `/analysis/parse-html` | POST | Parse HTML → liste forms, scripts inline, commentaires |
| `/analysis/headers` | POST | Audit d'en-têtes fournis (legacy v1.0) |
| `/analysis/blind-sqli` | POST | Compare 3 réponses pour détecter une blind SQLi |
| **`/analysis/fetch-headers`** | POST | **(nouveau)** Fetch côté serveur — récupère et analyse les **vrais** en-têtes HTTP |
| **`/analysis/cve-check`** | POST | **(nouveau)** Vérifie `{ name, version }` contre la base CVE locale |
| **`/analysis/correlate`** | POST | **(nouveau)** Corrélation bayésienne + déduplication des findings |

Le backend n'accepte que les requêtes venant d'une extension Chrome (`Origin: chrome-extension://...`) — voir `app.py`.

## 🛑 Arrêter le backend

`Ctrl+C` dans le terminal qui le fait tourner.

## 🐞 Problèmes courants

**"Python n'est pas reconnu"** → Installer Python 3.10+ et cocher *"Add Python to PATH"* pendant l'install.
**"Port 9876 déjà utilisé"** → Modifier `app.run(port=...)` dans `app.py`, et l'URL dans les options.
**"Acces refuse"** → Normal si vous testez depuis curl/Postman. Le backend bloque tout ce qui ne vient pas d'une extension. Pour debug, commentez `security_check()` dans `app.py`.
