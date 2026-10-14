"""
scanner.payloads — catalogue versionné de payloads.

Chaque famille de payloads vit dans un JSON séparé (xss.json, sqli.json, lfi.json...)
et est chargé à la demande via PayloadCatalog.

Le but : permettre à n'importe quel module d'enrichir/choisir un payload
selon le contexte sans dur-coder de listes dans le code Python.
"""
from .catalog import PayloadCatalog, get_payloads
__all__ = ["PayloadCatalog", "get_payloads"]
