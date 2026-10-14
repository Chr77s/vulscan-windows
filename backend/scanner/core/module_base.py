"""
Classe de base de tous les modules.

Chaque module hérite de `ScannerModule`, expose ses métadonnées et implémente
`scan(target, context) -> List[Finding]`.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any
import uuid
import time


@dataclass
class Finding:
    """Modèle standardisé d'une vulnérabilité détectée par un module."""
    type: str
    severity: str              # critical | high | medium | low | info
    description: str
    recommendation: str
    url: str
    title: str = ""
    parameter: str = ""
    payload: Optional[str] = None
    evidence: str = ""
    evidence_request: Optional[Dict[str, Any]] = None
    evidence_response: Optional[Dict[str, Any]] = None
    confidence: int = 80       # 0-100 (probabilité subjective)
    detection_method: str = "passive-server-analysis"
    source: str = "backend-module"
    cvss_base: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_id: Optional[str] = None
    references: List[Dict[str, str]] = field(default_factory=list)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    detected_at: int = field(default_factory=lambda: int(time.time() * 1000))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Adapter les clés au format utilisé côté extension
        d["detectionMethod"] = d.pop("detection_method")
        d["detectedAt"]      = d.pop("detected_at")
        d["cvssBase"]        = d.pop("cvss_base")
        d["cvssVector"]      = d.pop("cvss_vector")
        if d.get("cwe_id"):
            d["cwe"] = {"id": d["cwe_id"], "name": "", "url": f"https://cwe.mitre.org/data/definitions/{d['cwe_id'].replace('CWE-', '')}.html"}
        d.pop("cwe_id", None)
        if d.get("owasp_id"):
            d["owasp"] = {"id": d["owasp_id"], "name": "", "url": "https://owasp.org/Top10/"}
        d.pop("owasp_id", None)
        d["evidenceRequest"] = d.pop("evidence_request")
        d["evidenceResponse"] = d.pop("evidence_response")
        return d


class ScannerModule:
    """
    Classe de base — chaque détecteur en hérite.

    Métadonnées obligatoires :
        name        : identifiant court ("sqli", "xss", "headers"...)
        category    : famille ("injection", "headers", "info"...)
        title       : nom lisible
        description : à quoi sert ce module
        default_enabled : activé par défaut ?
    """
    name: str = "abstract"
    category: str = "uncategorized"
    title: str = "Module abstrait"
    description: str = ""
    default_enabled: bool = True

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self.options = options or {}

    # À surcharger
    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        raise NotImplementedError(f"scan() non implémenté dans {self.__class__.__name__}")

    @classmethod
    def metadata(cls) -> Dict[str, Any]:
        return {
            "name": cls.name,
            "category": cls.category,
            "title": cls.title,
            "description": cls.description,
            "default_enabled": cls.default_enabled,
        }
