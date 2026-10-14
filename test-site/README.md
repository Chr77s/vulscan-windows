# 🧃 JuiceCorp — Site de test pour VulnScan

Un site fictif **volontairement vulnérable** pour entraîner et démontrer l'extension VulnScan.

> ⚠️ **Ne déployez jamais ce site en production.** Il contient des failles intentionnelles.

## Lancement rapide

### Option A — Ouverture directe (recommandée pour test rapide)

Double-cliquez sur `index.html`. Chrome ouvre le site en `file://`. Toutes les vulns DOM sont scannables.

### Option B — Serveur local (recommandé pour tests réalistes)

Depuis le dossier `test-site/`, lancez un serveur HTTP simple :

```bash
# Python 3
python -m http.server 8000

# Node.js
npx http-server -p 8000
```

Puis ouvrez `http://localhost:8000` dans Chrome.

### Comment scanner

1. Installer / charger l'extension VulnScan dans Chrome (`chrome://extensions` → mode développeur → charger le dossier `extension/`).
2. Ouvrir une page du site.
3. Ouvrir les **DevTools** (F12) → onglet **VulnScan**.
4. Cliquer sur **▶ Lancer un scan**.
5. Naviguer entre les pages et relancer un scan sur chacune.

## Pages et vulnérabilités attendues

| Page | Vulnérabilités intentionnelles | Sévérité attendue |
|---|---|---|
| `index.html` | jQuery 1.7.2 obsolète · `eval()` inline · `document.write()` · email exposé | high / medium / low |
| `login.html` | Formulaire POST sans token CSRF · `eval()` sur input utilisateur · `innerHTML` dynamique | high / medium |
| `search.html` | XSS reflété via `innerHTML` + `document.write()` · `eval()` · stack trace dans commentaire HTML · chemin `/var/www/` | high |
| `profile.html` | Formulaire POST sans CSRF · clé API `sk_live_...` · secret HMAC · chemin absolu serveur · plusieurs emails | **critical** / medium |
| `comments.html` | jQuery 2.1.4 obsolète · Angular 1.6.5 vulnérable · POST sans CSRF · `innerHTML` + `document.write()` dynamiques | high / medium |
| `contact.html` | POST sans CSRF · 8 emails exposés · commentaire HTML révélant chemins absolus | medium / low |
| `debug.html` | Stack trace Python complet · clé API · secret JWT · access token · chemins `/var/www`, `/home/`, `C:\Users\` · emails admin | **critical** / high |

## Inventaire complet des vulnérabilités

Au total, **VulnScan** doit détecter (sur l'ensemble du site) :

- **XSS** : utilisations de `eval()`, `document.write()` et `.innerHTML` dynamiques (~12 occurrences)
- **CSRF** : 5 formulaires POST sans token CSRF
- **Bibliothèques obsolètes** : jQuery 1.7.2, jQuery 2.1.4, Angular 1.6.5
- **Données sensibles** :
  - Clés API et secrets (≥ 4 occurrences en sévérité critique)
  - Stack traces Python complètes (high)
  - Chemins absolus serveur `/var/www/`, `/home/`, `/etc/`, `C:\Users\` (medium)
  - 15+ adresses email exposées (low)

Soit environ **30 à 40 vulnérabilités** détectées au cumul des pages.

## Conseils pour le dashboard

- Utilisez les **chips de sévérité** pour filtrer rapidement (Critique, Élevé, Moyen…).
- Tapez `eval` ou `csrf` dans le champ de recherche pour filtrer par mot-clé.
- Le **score de risque** dans le KPI total donne une vue d'ensemble.
- Le **donut chart** montre la répartition par sévérité en un coup d'œil.
- Cliquez sur une vuln pour voir la **preuve**, l'**URL concernée** et la **recommandation OWASP**.
- Exportez le rapport en **JSON / HTML / CSV** depuis le pied de page.
