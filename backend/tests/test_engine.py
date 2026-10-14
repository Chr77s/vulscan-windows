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


def test_engine_run_records_per_module_log():
    from scanner.core.engine import ScannerEngine
    from scanner.core.module_base import ScannerModule, Finding

    class FakeModule(ScannerModule):
        name = "fake"
        category = "test"
        default_enabled = True
        def scan(self, target, context):
            return [Finding(type="fake", severity="low", description="d", recommendation="r", url=target)]

    engine = ScannerEngine()
    engine.register(FakeModule)
    engine.run("http://example.com", context={"crawled": {"urls": [], "forms": [], "api_endpoints": [], "stats": {}}}, enabled=["fake"], crawl=False)

    assert engine.last_module_log == [{"module": "fake", "findings": 1, "elapsed_ms": engine.last_module_log[0]["elapsed_ms"]}]
    assert engine.last_module_log[0]["elapsed_ms"] >= 0


def test_engine_run_records_crash_distinctly_in_module_log():
    """Fix 5 (final-fix-wave) : un module qui raise doit produire une entrée de
    last_module_log distinguable d'un succès à 0 finding (status: "error")."""
    from scanner.core.engine import ScannerEngine
    from scanner.core.module_base import ScannerModule

    class CrashingModule(ScannerModule):
        name = "crashing"
        category = "test"
        default_enabled = True

        def scan(self, target, context):
            raise RuntimeError("boom")

    engine = ScannerEngine()
    engine.register(CrashingModule)
    engine.run(
        "http://example.com",
        context={"crawled": {"urls": [], "forms": [], "api_endpoints": [], "stats": {}}},
        enabled=["crashing"],
        crawl=False,
    )

    assert len(engine.last_module_log) == 1
    entry = engine.last_module_log[0]
    assert entry["module"] == "crashing"
    assert entry["findings"] == 0
    assert entry["status"] == "error"
    assert "boom" in entry["error"]


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
