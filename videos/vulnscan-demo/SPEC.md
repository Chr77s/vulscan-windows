GOAL:    En 20s, le viewer comprend que VulnScan détecte de vraies failles web (XSS, SQLi,
         en-têtes manquants...) directement dans Chrome DevTools, scorées CVSS/CWE, exportables —
         puis va voir le dépôt GitHub.
OUTPUT:  HyperFrames, 1920x1080, 30fps
TIME:    20s x 30fps = 600 frames. Beats : 0-150 (titre) / 150-330 (findings) / 330-480 (chiffres) / 480-600 (CTA)
LOOK:    ground #0b1120 uni + grille 1px tous les 48px à 4% d'opacité blanche (texture "scan", pas de glow) ;
         ink #e2e8f0 ; un seul accent #818cf8 (indigo réel de la marque), utilisé uniquement sur le mot-clé
         du titre et le lien CTA ; display face Segoe UI/system-ui 800 72px tracking -2% ; body face idem 600 22px.
         Medium : mockup "fenêtre navigateur" (coins 14px, bordure 1px rgba(255,255,255,.08), ombre
         0/30px/60px rgba(13,22,36,.4) — valeurs reprises du vrai CSS du produit) contenant la vraie
         capture d'écran du popup (findings réels, pas de maquette inventée).
OBJECTS: icône "V" réelle (assets/icon.png, 96px), capture popup réelle (assets/popup.png, encadrée),
         badges de sévérité (couleurs réelles : critical #ef4444, high #f97316, medium #eab308, low #22c55e),
         nombre "30+", texte "JSON · SARIF · HTML".
MOTION:  enter = power3.out, exit = power2.in. Titre : slide-in X -40px→0 sur 24f. Tagline : fade+slide Y
         10px→0 sur 18f, démarre 10f après le titre (jamais simultané). Fenêtre popup : clip-path inset
         wipe gauche→droite sur 30f. Compteur 30+ : textContent 0→30 sur 36f (pas d'ease visuel, increment
         linéaire par frame). Chips export : stagger 8f entre chaque, slide Y 14px→0 sur 16f chacun.
SHOTS:
  1. f0-150   — icône + "VulnScan" slide depuis la gauche (24f) ; tagline "Scanner de vulnérabilités
                OWASP Top 10, dans Chrome DevTools" apparaît 10f après, tient jusqu'à f150.
  2. f150-330 — fenêtre navigateur avec la vraie capture popup se révèle par wipe (30f) ; à f210, ligne
                "4 failles détectées en quelques secondes" glisse depuis la droite (20f) sous la fenêtre.
  3. f330-480 — "30+" s'incrémente (36f), puis "modules de détection" apparaît (pas simultané) ; 3 chips
                "JSON" "SARIF" "HTML" arrivent en stagger 8f.
  4. f480-600 — icône (56px) + "github.com/Chr77s/vulscan-windows" en accent, fade+slide 16px→0 sur 20f,
                tient jusqu'à f600.
BANNED:  void sombre avec éléments flottants au centre ; glow/bloom/néon/lens flare ; dégradé violet/bleu
         en fond ; tout qui fade-in en même temps ; logo cantonné en coin tout du long ; titre sur capture
         assombrie ; labels d'angle / HUD décoratifs ; cartes avec ombre générique noire pure.
QA:      frame 75 (titre + tagline visibles), frame 240 (fenêtre popup révélée, non assombrie, lisible),
         frame 400 (compteur à 30, chips visibles), frame 560 (CTA lisible).
