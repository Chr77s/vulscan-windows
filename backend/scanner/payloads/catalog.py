"""
Loader centralisé pour les payloads JSON.

Schéma d'un fichier payloads/<famille>.json :
{
  "family": "xss",
  "version": "1.0.0",
  "categories": {
    "html_context":      [{"payload": "<script>...", "description": "...", "confidence_hint": 90}],
    "attribute_context": [...],
    ...
  }
}

Usage :
    from scanner.payloads import get_payloads
    xss = get_payloads("xss", category="html_context")  # liste de dicts
    all_lfi = get_payloads("lfi")                       # toutes catégories aplaties
"""
from __future__ import annotations
from typing import List, Dict, Any, Optional
import json
import os
import threading

_PAYLOADS_DIR = os.path.dirname(os.path.abspath(__file__))
_cache: Dict[str, Dict[str, Any]] = {}
_lock = threading.Lock()


class PayloadCatalog:
    """Accesseur typé au catalogue."""

    @staticmethod
    def load(family: str) -> Dict[str, Any]:
        with _lock:
            if family in _cache:
                return _cache[family]
            path = os.path.join(_PAYLOADS_DIR, f"{family}.json")
            if not os.path.exists(path):
                return {"family": family, "version": "0.0.0", "categories": {}}
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            _cache[family] = data
            return data

    @staticmethod
    def list_families() -> List[str]:
        out = []
        for f in os.listdir(_PAYLOADS_DIR):
            if f.endswith(".json"):
                out.append(f[:-5])
        return sorted(out)


_DEPTH_ORDER = {"basic": 0, "extended": 1, "aggressive": 2}


def get_payloads(family: str, category: Optional[str] = None, depth: Optional[str] = None) -> List[Dict[str, Any]]:
    """Retourne les payloads d'une famille (et optionnellement d'une catégorie),
    filtrés de façon cumulative par palier de profondeur si `depth` est fourni."""
    data = PayloadCatalog.load(family)
    categories = data.get("categories", {})
    if category:
        items = [{**item, "category": category} for item in categories.get(category, [])]
    else:
        items = []
        for cat_name, cat_items in categories.items():
            for item in cat_items:
                items.append({**item, "category": cat_name})
    if depth is None:
        return items
    max_rank = _DEPTH_ORDER.get(depth, _DEPTH_ORDER["aggressive"])
    return [it for it in items if _DEPTH_ORDER.get(it.get("depth", "basic"), 0) <= max_rank]
