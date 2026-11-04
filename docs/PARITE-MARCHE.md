# VulnScan — Parité avec les leaders du marché

Analyse d'écart honnête entre VulnScan et les scanners de référence
(Burp Suite Pro, Acunetix, Invicti/Netsparker, OWASP ZAP), puis liste
priorisée des modifications pour les égaler. Daté du 2026-11-05.

Principe directeur du projet : **détection honnête et précise**. Chaque
amélioration ci-dessous doit préserver la règle « aucune preuve = aucun
finding » et le différentiel par rapport à une baseline.

---

## Ce que VulnScan a déjà (base solide)

- 27 modules actifs/passifs, moteur à fusion bayésienne, inférence contextuelle.
- Catalogue de payloads porté par oracles (signature/`expected`/`dbms`), 2 passes d'enrichissement.
- Scan asynchrone (jobs backend, budget temps 260 s, résultats partiels), 1 scan à la fois.
- Confirmation DOM XSS dans un onglet caché (exécution réellement observée).
- Canari OOB (`routes/oob.py`), triage Confirmé/Faux positif persisté, diff de scans, tendance de risque.
- Exports JSON/CSV/HTML/PDF/XML, historique SQLite.

---

## Écarts vs leaders — modifications priorisées

### Tier 1 — plus fort levier (ferme les plus gros écarts)

1. **Scan authentifié robuste (login recorder + gestion de session)**
   *Leaders :* séquence de login rejouable, détection de dé-connexion, refresh de token/CSRF, re-auth automatique.
   *VulnScan :* contexte d'auth statique (cookies/headers/basic) seulement.
   *Modif :* enregistrer une séquence de connexion (via l'onglet caché déjà utilisé pour DOM XSS), détecter la perte de session (motif de page de login) et ré-authentifier en cours de scan ; champ « est-on toujours connecté ? » dans le contexte.
   *Effort :* élevé.

2. **OOB/OAST complet et corrélé (type Burp Collaborator / interactsh)**
   *Leaders :* détection des vulns *aveugles* (SSRF, XXE, RCE, XSS stocké, SQLi blind) via rappel DNS/HTTP hors bande.
   *VulnScan :* canari OOB basique, non corrélé à chaque payload.
   *Modif :* identifiant unique par payload injecté → corrélation stricte rappel↔finding ; couvrir SSRF/XXE/cmdi/XSS-stocké aveugles. Oracle = réception du rappel, imparable.
   *Effort :* élevé (nécessite un endpoint public ou un service interactsh).

3. **Crawl des SPA (rendu JavaScript)**
   *Leaders :* rendu headless, suivi d'état, découverte des routes générées en JS.
   *VulnScan :* crawler profondeur 1, 30 pages, formulaires statiques — rate le contenu rendu côté client.
   *Modif :* réutiliser l'onglet caché pour rendre la page et extraire liens/formulaires/endpoints `fetch`/XHR après exécution JS.
   *Effort :* moyen-élevé.

4. **Équité de budget entre modules (ordonnancement)**
   *Constat mesuré (2026-11-05) :* `form-fuzzer` et `header-injection` consomment ~117–160 s chacun et, selon l'ordre, affament les modules suivants.
   *Modif :* plafond de temps par module (s'arrêter quand il reste < réserve pour les modules restants) **ou** répartition équitable du budget ; déjà pointé, non implémenté sur demande.
   *Effort :* faible-moyen.

### Tier 2 — précision et couverture

5. **Confiance apprise depuis le triage** (conçu, non implémenté)
   Ajuster le score de confiance d'une (type, méthode de détection) selon les Confirmé/Faux positif de l'utilisateur, + mémoire de triage par empreinte de cible. Voir la spec de brainstorming associée.

6. **Contrôle d'accès / IDOR à deux sessions**
   *Leaders :* rejouent une requête d'un compte A avec la session d'un compte B pour prouver l'accès horizontal.
   *Modif :* accepter deux contextes d'auth et comparer les réponses ; preuve = ressource de A lisible par B.

7. **OWASP API Top 10**
   BOLA/BOPLA (object/property level authorization), mass assignment, consommation de ressources, SSRF API. S'appuyer sur `json-fuzzer`/`graphql` existants + introspection OpenAPI.

8. **XSS stocké et DOM étendu**
   *VulnScan :* DOM XSS confirmé, réfléchi confirmé.
   *Modif :* injecter puis re-crawler pour détecter la persistance (stocké) ; élargir les sinks DOM (`innerHTML`, `eval`, `location`, `postMessage`).

9. **Analyse passive approfondie**
   Secrets/clés dans le JS et les source maps, contenu mixte, attributs de cookie, analyse fine de CSP (directives faibles `unsafe-inline`/`*`), prototype pollution côté client.

### Tier 3 — intégration et restitution

10. **Mode CLI headless + sortie SARIF** pour CI/CD (fail-on-severity), en réutilisant le moteur backend sans extension.

11. **Rapports de conformité** : mapping OWASP ASVS / PCI-DSS / API Top 10, résumé exécutif, export vers un suivi de tickets.

12. **Re-test en un clic** d'un finding (rejouer `evidence_request` et comparer) — la preuve est déjà stockée, il manque le bouton + la route.

13. **Détection avancée** : request smuggling (HTTP/1.1 desync), désérialisation, injection d'en-tête Host corrélée OOB, confusion d'algorithme JWT (`kid`, `jku`), CORS avec `credentials`.

---

## Séquence recommandée

Tier 1.4 (équité budget, faible effort, débloque la couverture) → Tier 2.5
(confiance apprise, déjà conçue) → Tier 1.2 (OOB corrélé, gros gain de
détection aveugle) → Tier 1.1 et 1.3 (auth + SPA, qui se partagent l'onglet
caché) → Tier 2/3 au fil de l'eau.

Chaque item suit le processus du projet : brainstorming → spec → plan →
développement piloté par sous-agents, avec vérification live sur cibles
publiques autorisées (ginandjuice.shop, public-firing-range).
