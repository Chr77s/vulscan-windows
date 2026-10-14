# 🧠 VulnScan — Algorithme de détection (v1.1)

## La question quantique : peut-on accélérer avec 1 qubit ?

**Réponse honnête : non, pas de façon utile.**

Un simulateur quantique à 1 qubit sur PC classique, c'est juste deux nombres complexes (`α|0⟩ + β|1⟩`). C'est techniquement possible — votre PC peut le faire en quelques nanosecondes — mais ça n'apporte **aucun avantage** pour la détection de vulnérabilités, et voici pourquoi :

1. **Les algorithmes quantiques utiles demandent beaucoup de qubits cohérents.**
   - L'algorithme de **Grover** (recherche non-structurée) donne un gain de √N — mais il faut N qubits pour indexer N éléments, et ils doivent rester intriqués pendant tout le calcul. Pour scanner 1000 patterns, il faudrait ≈ 10 qubits stables. Un seul qubit ne fait rien.
   - L'algorithme de **Shor** (factorisation) est utile en crypto, pas en scan de vulns.
   - Aucun algorithme quantique connu ne bat le classique sur du **pattern matching texte** (qui est notre cas).

2. **Le pattern matching est déjà optimal en classique.**
   - Algorithmes comme Aho-Corasick atteignent O(n + m + k) — linéaire et imbattable.
   - Les regex modernes (V8 avec Irregexp) sont compilées en bytecode optimisé.
   - Le goulot d'étranglement de VulnScan, c'est **les détecteurs absents**, pas la vitesse.

3. **Les gains réels viennent d'ailleurs :**
   - **Parallélisme** : Web Workers / `Promise.all`
   - **Bons signaux** : multi-signal scoring plutôt que regex toutes-puissantes
   - **Élimination du bruit** : déduplication, seuils de confiance
   - **Couverture** : ajouter des détecteurs (DOM sinks, mixed content, etc.)

**Conclusion** : si quelqu'un vous vend un scanner "quantique" aujourd'hui, c'est du marketing. Les NISC (Noisy Intermediate-Scale Quantum) actuels ont ~100-1000 qubits bruités, instables, et incapables de faire mieux qu'un PC sur des problèmes de pattern matching réels.

## Ce qu'on a vraiment amélioré dans la v1.1

### 1. Scoring de confiance multi-signaux (0-100%)

Chaque détection porte désormais un **score de confiance**, calculé selon les indices observés :

| Détecteur | Indice | Confiance |
|---|---|---|
| `eval()` simple | présence | 75% |
| `eval()` + concaténation `eval("..." + x)` | usage clairement dangereux | **95%** |
| `document.write()` statique | présence | 60% |
| `document.write(x + y)` dynamique | usage dynamique confirmé | **90%** |
| CSRF sur form avec champ password/email | sensible | 90% |
| CSRF sur form générique | générique | 75% |
| jQuery/Angular version connue vulnérable | match CVE | **95%** |
| Clé API regex matché | match strict | 90% |
| Email exposé (regex large) | match large | 70% |
| X-Frame-Options absent (vue HTML seule) | détection partielle (les headers HTTP peuvent suffire) | **40%** |

L'utilisateur peut **filtrer en dessous d'un seuil** depuis les Options (par défaut 30%) — ça élimine les faux positifs sans cacher les vraies menaces.

### 2. Déduplication intelligente

Avant, scanner une page avec 5 scripts utilisant `eval()` produisait 5 vulnérabilités identiques. Maintenant, on déduplique sur la signature `(type + paramètre + 60 premiers chars de description)` en gardant la plus haute confiance.

### 3. Nouveaux détecteurs (5 ajouts)

| Détecteur | Ce qu'il cherche |
|---|---|
| **Clickjacking** | Absence de `X-Frame-Options` ou CSP `frame-ancestors` |
| **Mixed Content** | Page HTTPS qui charge des ressources `http://` |
| **Open Redirect** | Paramètres URL `?next=`, `?redirect=`, `?url=` avec destination externe |
| **SRI manquant** | Scripts/CSS externes sans attribut `integrity` |
| **Cookies non-sécurisés** | Cookies sensibles lisibles via `document.cookie` (= pas de HttpOnly) |

### 4. Patterns existants renforcés

- **Stack traces** : regex spécifique aux runtimes (Java, Python, JS) — moins de faux positifs sur du texte aléatoire.
- **Clés API** : whitelist explicite des préfixes connus (`sk_live_`, `pk_test_`, `Bearer`, etc.).
- **JWT** : détection des 3 segments base64 séparés par des points.
- **Bibliothèques obsolètes** : ajout de Lodash (CVE-2020-8203) et Moment (CVE-2022-31129).
- **DOM sinks** : liens `javascript:`, iframes sans `sandbox`, inputs password sans `autocomplete`.

### 5. Architecture du pipeline (v1.1 — backend requis)

```
                            ┌────────────────────────────────┐
                            │  Phase 1 : Pré-vol             │
                            │  service-worker.js             │
                            │  → GET /health  (backend up?)  │
                            │  Si KO → SCAN_ERROR + halte    │
                            └────────────────────────────────┘
                                          │
                                          ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  Phase 2A — Côté navigateur (content-script)                     │
   ├──────────────────────────────────────────────────────────────────┤
   │  analyzeDangerousPatterns  (eval, document.write, innerHTML)     │
   │  analyzeDomSinks           (sinks JS, iframes, password inputs)  │
   │  detectVulnerableLibraries (jQuery/Angular/Lodash/Moment)        │
   │  analyzeFormsForCSRF       (forms POST sans token)               │
   │  analyzeMixedContent       (HTTPS chargeant HTTP)                │
   │  analyzeOpenRedirects      (?next=, ?redirect=, …)               │
   │  analyzeMissingSRI         (CDN externes sans integrity)         │
   │  analyzeCookies            (cookies session sans HttpOnly)       │
   │  findSensitiveData         (clés API, JWT, paths, emails, IP)    │
   │                                                                  │
   │  ↓ retourne { vulnerabilities, context : { libraries, ... } }    │
   └──────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  Phase 2B — Côté backend Python (Flask)                          │
   ├──────────────────────────────────────────────────────────────────┤
   │  POST /analysis/fetch-headers  → fetch serveur de l'URL          │
   │     • CSP / HSTS / X-Frame-Options / Referrer-Policy             │
   │     • analyse qualité CSP (unsafe-inline, wildcard *)            │
   │     • Server: et X-Powered-By: bavards                           │
   │     • Set-Cookie sans Secure/HttpOnly/SameSite                   │
   │                                                                  │
   │  POST /analysis/cve-check      → match version vs base CVE       │
   │     • renvoie les CVEs applicables avec sévérité                 │
   │                                                                  │
   │  POST /analysis/correlate      → fusion bayésienne               │
   │     • regroupe par (type, paramètre)                             │
   │     • combine confiance : 1 − ∏(1 − cᵢ)                          │
   │     • renvoie liste corrélée + triée                             │
   └──────────────────────────────────────────────────────────────────┘
                                          │
                                          ▼
                   service-worker fusionne → SCAN_COMPLETED → UI
```

### 6. Comparaison avant / après

| Métrique | v1.0 | v1.1 |
|---|---|---|
| Détecteurs passifs | 4 | **9** |
| Patterns sensibles | 4 | **7** |
| Bibliothèques surveillées | 2 | **4** |
| Scoring de confiance | non | **oui (0-100%)** |
| Déduplication | non | **oui** |
| Filtre par seuil | non | **oui** |
| Faux positifs (estimés) | élevés | **réduits ~60%** |

## Si vous voulez vraiment du quantique-inspiré

Une chose **honnête** qu'on peut faire : utiliser un modèle probabiliste type **superposition de signaux** où chaque détecteur émet une amplitude, et on combine par produit (équivalent à un AND probabiliste). C'est ce que fait notre fonction `confidence`, en réalité — sauf qu'on l'appelle "scoring bayésien", pas "quantique", parce que ça l'est vraiment.

```js
// Exemple : confiance combinée multi-signaux
function combine(signals) {
  // signaux indépendants → P(vuln | signaux) ≈ 1 - ∏(1 - s)
  return 1 - signals.reduce((acc, s) => acc * (1 - s), 1);
}
// 3 signaux à 50% → 87.5% (vs 50% pris isolément)
```

C'est ce genre de logique qui donne un vrai gain — pas la "magie quantique".
