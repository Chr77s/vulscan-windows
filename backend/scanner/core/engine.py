"""
Moteur de scan — orchestre les modules.

Usage :
    engine = ScannerEngine()
    engine.register_all()                  # charge tous les modules disponibles
    findings = engine.run("https://...", context, enabled=["sqli", "headers"])

Le moteur applique aussi un **scoring bayésien** par regroupement (type, parameter)
pour combiner plusieurs signaux : confidence = 1 - Π(1 - cᵢ).
"""
from __future__ import annotations
from typing import List, Dict, Any, Optional, Type
import importlib
import logging
import pkgutil
import time

from .module_base import ScannerModule, Finding

logger = logging.getLogger("vulnscan.engine")


class ScannerEngine:
    def __init__(self):
        self._modules: Dict[str, Type[ScannerModule]] = {}
        self.last_module_log: List[Dict[str, Any]] = []

    # -----------------------------------------------------------------
    # Enregistrement
    # -----------------------------------------------------------------
    def register(self, module_cls: Type[ScannerModule]) -> None:
        self._modules[module_cls.name] = module_cls
        logger.info(f"Module enregistré : {module_cls.name} ({module_cls.category})")

    def register_all(self, package: str = "scanner.modules") -> None:
        """Auto-découverte de tous les modules dans le package donné."""
        pkg = importlib.import_module(package)
        for finder, modname, ispkg in pkgutil.walk_packages(pkg.__path__, prefix=package + "."):
            if ispkg:
                continue
            try:
                submod = importlib.import_module(modname)
            except Exception as e:
                logger.warning(f"Impossible de charger {modname} : {e}")
                continue
            for attr in dir(submod):
                obj = getattr(submod, attr)
                if (
                    isinstance(obj, type)
                    and issubclass(obj, ScannerModule)
                    and obj is not ScannerModule
                ):
                    self.register(obj)

    def list_modules(self) -> List[Dict[str, Any]]:
        return [cls.metadata() for cls in self._modules.values()]

    # -----------------------------------------------------------------
    # Exécution
    # -----------------------------------------------------------------
    def run(
        self,
        target: str,
        context: Optional[Dict[str, Any]] = None,
        enabled: Optional[List[str]] = None,
        crawl: bool = True,
    ) -> List[Finding]:
        # `context or {}` serait un piège ici : si l'appelant passe un dict
        # vide (valide, pas "pas de contexte"), `{} or {}` vaut le second `{}`
        # (le premier est falsy) et remplace la référence de l'appelant par un
        # nouveau dict — toute écriture faite ici (crawled, module_log, etc.)
        # deviendrait invisible pour l'appelant. Seul `None` doit déclencher
        # un nouveau dict ; un dict vide explicite doit garder son identité.
        if context is None:
            context = {}
        findings: List[Finding] = []

        # =========================================================
        # PHASE 0 — Crawler / discovery (avant les modules d'injection)
        # =========================================================
        if crawl and "crawled" not in context:
            try:
                from .crawler import Crawler
                crawler = Crawler(max_depth=1, max_pages=30)
                context["crawled"] = crawler.crawl(target, auth=context.get("auth"))
                logger.info(f"Crawler : {context['crawled']['stats']}")
            except Exception as e:
                logger.warning(f"Crawler échoué : {e}")
                context["crawled"] = {
                    "seed": target, "urls": [target],
                    "forms": [], "api_endpoints": [],
                    "stats": {"pages_visited": 0},
                }

        modules_to_run = (
            [self._modules[n] for n in enabled if n in self._modules]
            if enabled is not None
            else [cls for cls in self._modules.values() if cls.default_enabled]
        )

        module_log: List[Dict[str, Any]] = []
        for cls in modules_to_run:
            t0 = time.monotonic()
            try:
                instance = cls()
                result = instance.scan(target, context) or []
                logger.info(f"  ↳ {cls.name} : {len(result)} findings")
                findings.extend(result)
                module_log.append({
                    "module": cls.name,
                    "findings": len(result),
                    "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                })
            except Exception as e:
                logger.exception(f"Module {cls.name} a crashé : {e}")
                module_log.append({
                    "module": cls.name,
                    "findings": 0,
                    "elapsed_ms": round((time.monotonic() - t0) * 1000, 1),
                    # Fix 5 (final-fix-wave) : distingue un crash d'un "0 findings"
                    # propre — sans ce champ, panel.js affichait les deux de façon
                    # identique ("✓ module — 0 findings"), masquant le crash.
                    "status": "error",
                    "error": str(e),
                })

        # Fusion bayésienne
        merged = self._bayesian_merge(findings)

        # Inférence contextuelle (règles d'ajustement)
        try:
            from .inference import apply_inference
            inference_log = apply_inference(merged)
            logger.info(f"Inférence : {len(inference_log['changes'])} ajustements")
        except Exception as e:
            logger.warning(f"Inférence ignorée : {e}")

        # Concurrency fix (Round 7 I4 follow-up) : `context` est toujours une
        # nouvelle instance par requête HTTP (routes/scanner_engine.py crée
        # `context = data.get("context", {})` à chaque appel), contrairement à
        # `self` qui est le moteur singleton partagé par toutes les requêtes
        # sous Flask threaded=True — deux /scanner/run concurrents pouvaient
        # donc se lire le journal l'un de l'autre via self.last_module_log.
        # On écrit désormais le journal dans context en plus de self ; self
        # reste pour l'usage direct/mono-thread (scripts, tests existants),
        # non concurrent par nature.
        context["module_log"] = module_log
        self.last_module_log = module_log
        return merged

    # -----------------------------------------------------------------
    # Scoring bayésien — combinaison de signaux indépendants
    # -----------------------------------------------------------------
    @staticmethod
    def _bayesian_merge(findings: List[Finding]) -> List[Finding]:
        groups: Dict[tuple, List[Finding]] = {}
        for f in findings:
            key = (f.type, (f.parameter or "")[:60])
            groups.setdefault(key, []).append(f)

        SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        merged: List[Finding] = []
        for bucket in groups.values():
            if len(bucket) == 1:
                merged.append(bucket[0])
                continue

            # P(vuln | n signaux indépendants) = 1 - Π(1 - cᵢ/100)
            product = 1.0
            for v in bucket:
                product *= (1.0 - v.confidence / 100.0)
            combined = int(round((1.0 - product) * 100))

            # Représentant = plus haute confiance, mais on remonte le score combiné
            rep = max(bucket, key=lambda x: x.confidence)
            rep.confidence = combined
            rep.severity = max(bucket, key=lambda x: SEV_RANK.get(x.severity, 0)).severity
            rep.description = f"{rep.description} [+{len(bucket) - 1} signaux corrélés, confiance bayésienne combinée]"
            rep.source = "backend-correlated"
            merged.append(rep)

        # Tri final
        merged.sort(key=lambda f: (-SEV_RANK.get(f.severity, 0), -f.confidence))
        return merged
