# 🧪 WebLab — Laboratoire de pentest pédagogique

> ⚠️ **À usage strictement local et pédagogique.** Ce projet contient des vulnérabilités **délibérément introduites** pour entraîner un scanner ou s'exercer au pentest. Ne le déployez jamais sur Internet.

## Installation sous WAMP (Windows)

1. **Copier le dossier WebLab dans WAMP** :
   ```
   C:\wamp64\www\WebLab\
   ```

2. **Démarrer WAMP** → l'icône doit être verte (Apache + MySQL OK).

3. **Créer la base de données** :
   - Ouvrir <http://localhost/phpmyadmin>
   - Importer `database/schema.sql` puis `database/seed.sql`
   - (ou via CLI : `mysql -u root < database/schema.sql && mysql -u root weblab < database/seed.sql`)

4. **Vérifier la config DB** dans `config.php` :
   ```php
   $DB_HOST = "localhost"; $DB_NAME = "weblab"; $DB_USER = "root"; $DB_PASS = "";
   ```

5. **Ouvrir** <http://localhost/WebLab/> dans Chrome.

## 🐛 Vulnérabilités introduites (par page)

| Page | Vulnérabilités | OWASP |
|---|---|---|
| `index.php` | Pas de protection clickjacking, en-têtes manquants | A05 |
| `login.php` | SQLi error/blind sur `username`/`password`, pas de rate-limiting, message d'erreur révélateur | A03, A07 |
| `register.php` | Faible politique de mot de passe, pas de hashing (md5 en clair) | A02, A07 |
| `search.php?q=` | XSS réfléchi via `q` | A03 |
| `product.php?id=` | IDOR (id incrémental, pas de check ownership), SQLi sur `id` | A01, A03 |
| `profile.php` | Stored XSS via le champ `bio`, CSRF (pas de token sur update) | A03, A01 |
| `comments.php` | Stored XSS + IDOR (suppression d'autres commentaires) | A03, A01 |
| `include.php?page=` | LFI (`include $_GET['page']`) | A03 |
| `upload.php` | File upload non vérifié (extension, MIME), accessible publiquement | A05, A08 |
| `redirect.php?url=` | Open Redirect | A01 |
| `api/users.php` | Pas d'authentification, retourne tous les users + hash | A01, A02 |
| `api/jwt.php` | JWT signé avec `secret123` (devine­able) | A02, A07 |
| `admin/` | Panneau admin sans auth, listable via `robots.txt` | A01, A07 |
| `backup.bak`, `.env`, `.git/` | Fichiers de backup et config accessibles | A05 |
| `crlf.php?lang=` | CRLF injection dans le header Set-Cookie | A03 |
| `sessions.php` | Session tokens prévisibles `md5(time())` | A07 |
| `admin/delete_user.php?id=` | Action destructive sans auth + CSRF + SQLi en GET | A01 |
| `.git-exposed-demo/HEAD`, `.git-exposed-demo/config` | Repo Git "leaké" (renommé pour ne pas conflit OS — voir note) | A05 |

> **Note .git/** : Le dossier `.git/` peut être bloqué/géré par Windows/IDE. Si tu veux le simuler tel quel pour le scan : renomme `.git-exposed-demo/` en `.git/` après installation dans WAMP, OU exécute `git init && touch dummy && git add . && git commit -m demo` dans le dossier WebLab pour générer un vrai `.git/`. Le module `file-exposure` détecte `.git/HEAD` exact.

## Comptes de test (créés par seed.sql)

| Username | Mot de passe | Rôle | Notes |
|---|---|---|---|
| `admin` | `admin123` | admin | Compte par défaut (creds faibles) |
| `alice` | `password` | user | Profil avec bio (test XSS stockée) |
| `bob`   | `qwerty`   | user | A des commandes (test IDOR) |
| `charlie` | `letmein` | user | Compte de test |

## 🔍 Comment lancer un scan avec VulnScan

1. Vérifier que le backend Python tourne (`backend/start.bat`).
2. Naviguer sur les différentes pages de WebLab dans Chrome.
3. F12 → onglet **VulnScan** → **▶ Lancer un scan**.
4. Les détecteurs serveur (headers, SQLi, XSS) doivent remonter une trentaine de findings selon la page.
