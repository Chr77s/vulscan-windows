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


def test_engine_run_writes_module_log_to_context_not_only_self():
    """Concurrency fix (Round 7 I4 follow-up) : sous Flask threaded=True, le
    moteur est un singleton partagé entre requêtes. last_module_log porté
    uniquement par self peut être écrasé par une requête concurrente avant
    que l'appelant d'une autre requête ne le lise. Le journal doit donc aussi
    être accessible via `context`, qui est toujours une nouvelle instance par
    requête HTTP — ce test prouve que deux appels sur le MÊME moteur partagé,
    avec deux `context` différents, ne mélangent pas leurs journaux."""
    engine = ScannerEngine()
    engine.register(_FakeModule)

    class _OtherModule(ScannerModule):
        name = "other-test"
        category = "test"
        default_enabled = True

        def scan(self, target, context):
            return []

    engine.register(_OtherModule)

    context_a: dict = {}
    context_b: dict = {}
    engine.run("http://a.test", context=context_a, enabled=["fake-test"], crawl=False)
    engine.run("http://b.test", context=context_b, enabled=["other-test"], crawl=False)

    assert [e["module"] for e in context_a["module_log"]] == ["fake-test"]
    assert [e["module"] for e in context_b["module_log"]] == ["other-test"]


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


# ---------------------------------------------------------------------
# Budget temps (time_budget_s -> deadline)
# ---------------------------------------------------------------------
def _budget_module(mod_name, past_deadline=False, crash=False):
    import time

    class _M(ScannerModule):
        name = mod_name
        category = "test"
        default_enabled = True

        def scan(self, target, context):
            if past_deadline:
                context["deadline"] = time.monotonic() - 1
            if crash:
                raise RuntimeError("boom")
            return [Finding(type=f"t-{mod_name}", severity="low", url=target,
                            description="d", recommendation="r")]

    return _M


def _run_budget(mods, context):
    engine = ScannerEngine()
    for m in mods:
        engine.register(m)
    findings = engine.run("http://x.test", context=context,
                          enabled=[m.name for m in mods], crawl=False)
    return findings, {e["module"]: e for e in context["module_log"]}


def test_budget_skips_modules_after_deadline():
    ctx = {"time_budget_s": 30}
    findings, log = _run_budget(
        [_budget_module("a", past_deadline=True), _budget_module("b"), _budget_module("c")], ctx)
    assert [f.type for f in findings] == ["t-a"]
    for n in ("b", "c"):
        assert log[n] == {"module": n, "findings": 0, "elapsed_ms": 0,
                          "status": "skipped", "reason": "time_budget"}
    assert "status" not in log["a"]


def test_no_budget_adds_no_deadline():
    ctx = {}
    findings, log = _run_budget([_budget_module("a"), _budget_module("b")], ctx)
    assert "deadline" not in ctx
    assert len(findings) == 2
    assert all("status" not in e for e in log.values())


def test_budget_string_and_garbage():
    ctx = {"time_budget_s": "45"}
    _run_budget([_budget_module("a")], ctx)
    assert "deadline" in ctx
    for bad in ("abc", 0, -5, None):
        ctx = {"time_budget_s": bad}
        _run_budget([_budget_module("a")], ctx)
        assert "deadline" not in ctx


def test_existing_deadline_not_overwritten():
    ctx = {"time_budget_s": 30, "deadline": 123.0}
    findings, log = _run_budget([_budget_module("a"), _budget_module("b")], ctx)
    assert ctx["deadline"] == 123.0
    assert findings == []
    assert all(e["status"] == "skipped" for e in log.values())


def _slow_start_module(mod_name):
    m = _budget_module(mod_name)
    m.min_time_to_start_s = 30
    return m


def test_module_needing_more_time_than_left_is_skipped():
    import time
    ctx = {"deadline": time.monotonic() + 10}
    findings, log = _run_budget([_slow_start_module("slow"), _budget_module("fast")], ctx)
    assert log["slow"] == {"module": "slow", "findings": 0, "elapsed_ms": 0,
                           "status": "skipped", "reason": "time_budget"}
    assert [f.type for f in findings] == ["t-fast"]


def test_module_needing_less_time_than_left_runs():
    import time
    ctx = {"deadline": time.monotonic() + 40}
    findings, log = _run_budget([_slow_start_module("slow")], ctx)
    assert "status" not in log["slow"]
    assert [f.type for f in findings] == ["t-slow"]


def test_min_time_to_start_ignored_without_budget():
    findings, log = _run_budget([_slow_start_module("slow")], {})
    assert "status" not in log["slow"]
    assert len(findings) == 1


def test_deadline_bypassing_modules_declare_min_time_to_start():
    from scanner.modules.ssl_tls import SslTlsModule
    from scanner.modules.subdomain_enum import SubdomainEnumModule
    assert ScannerModule.min_time_to_start_s == 0.0
    assert SslTlsModule.min_time_to_start_s == 30.0
    assert SubdomainEnumModule.min_time_to_start_s == 25.0


def test_crash_after_deadline_still_logged_as_error():
    ctx = {"time_budget_s": 30}
    _, log = _run_budget([_budget_module("a", past_deadline=True, crash=True),
                          _budget_module("b")], ctx)
    assert log["a"]["status"] == "error"
    assert log["b"]["status"] == "skipped"
