"""Tier 1.4 — équité de budget entre modules (engine._fair_deadline)."""
from scanner.core.engine import _fair_deadline


def test_no_global_deadline_means_no_cap():
    assert _fair_deadline(0.0, None, 5) is None


def test_last_module_gets_all_remaining():
    assert _fair_deadline(0.0, 100.0, 1) == 100.0


def test_fair_share_split():
    # 100 s restants, 5 modules restants -> 20 s pour le module courant
    assert _fair_deadline(0.0, 100.0, 5) == 20.0
    assert _fair_deadline(0.0, 100.0, 4) == 25.0


def test_share_never_exceeds_global():
    d = _fair_deadline(10.0, 40.0, 3)   # 30 restants / 3 = 10 -> 20, < 40
    assert d == 20.0


def test_past_deadline_returns_global():
    assert _fair_deadline(100.0, 50.0, 5) == 50.0
