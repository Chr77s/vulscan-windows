#!/usr/bin/env bash
# ============================================================
#  VulnScan Backend - lanceur Linux/macOS
# ============================================================
set -e
cd "$(dirname "$0")"

if ! command -v python3 &> /dev/null; then
  echo "[ERREUR] python3 n'est pas installé."
  exit 1
fi

if [ ! -d ".venv" ]; then
  echo "[VulnScan] Création de l'environnement virtuel..."
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[VulnScan] Installation des dépendances..."
pip install --quiet -r requirements.txt

echo ""
echo "============================================================"
echo "  VulnScan Backend démarre sur http://127.0.0.1:9876"
echo "  Ctrl+C pour arrêter"
echo "============================================================"
echo ""
python app.py
