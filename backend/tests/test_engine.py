"""Tests unitaires du moteur (auto-découverte, fusion bayésienne)."""
import pytest
from scanner.core.engine import ScannerEngine
from scanner.core.module_base import ScannerModule, Finding


class _FakeModule(ScannerModule):
    name = "fake-test"
    category = "test"
    title = "Fake test module"
    description = "Émet 2 findings synthétiques."
    default_enabled = True

    def scan(self, target, context):
        return [
            Finding(type="xss", severity="high", url=target,
                    description="Signal 1", recommendation="Rec",
                    parameter="p", confidence=60),
            Finding(type="xss", severity="medium", url=target,
                    description="Signal 2 (dédoublon)", recommendation="Rec",
                    parameter="p", confidence=70),
        ]


def test_engine_register_and_metadata():
    engine = ScannerEngine()
    engine.register(_FakeModule)
    meta = engine.list_modules()
    assert any(m["name"] == "fake-test" for m in meta)


def test_engine_run_executes_modules():
    engine = ScannerEngine()
    engine.register(_FakeModule)
    findings = engine.run("http://test.local", context={}, enabled=["fake-test"])
    # 2 findings → 1 après fusion bayésienne (même type+param)
    assert len(findings) == 1
    f = findings[0]
    # confidence combinée = 1 - (1 - 0.60) * (1 - 0.70) = 1 - 0.12 = 0.88
    assert f.confidence == 88
    # sévérité = max (high > medium)
    assert f.severity == "high"


def test_engine_run_disabled_module():
    engine = ScannerEngine()
    engine.register(_FakeModule)
    # Lance avec liste vide d'enabled → aucun module
    findings = engine.run("http://test.local", context={}, enabled=[])
    assert findings == []


def test_engine_auto_discovery():
    """Vérifie qu'on découvre bien les modules du package scanner.modules."""
    engine = ScannerEngine()
    engine.register_all()
    names = {m["name"] for m in engine.list_modules()}
    # Présence des modules livrés Round 1+2
    expected = {"headers", "info-disclosure", "sqli", "xss", "lfi", "ssrf",
                "command-injection", "open-redirect", "idor", "jwt-analysis",
                "cors-misconfig", "xxe",
                # Round 3
                "dir-bruteforce", "tech-fingerprint", "file-exposure", "rate-limit",
                # Round 4 — surface d'attaque étendue
                "form-fuzzer", "header-injection", "param-discovery", "json-fuzzer",
                # Round 5 — pro-grade (Option A)
                "ssl-tls", "graphql",
                # Round 5 — pro-grade (Option B : suite)
                "waf-detect", "race-conditions", "subdomain-enum"}
    assert expected.issubset(names), f"Modules manquants : {expected - names}"
