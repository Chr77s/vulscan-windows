"""
conftest.py — fixtures pytest partagées.

Force sys.path à inclure le dossier parent (backend/) pour permettre les imports
`from scanner...` et `from database...`.
"""
import sys
import os

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)
