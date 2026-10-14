# Round 6 — Detection Engine Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give VulnScan's backend scan engine a declarative matcher system, reproducible request/response evidence, persistent triage, two new injection modules (SSTI, NoSQLi), a global rate limiter, and — because it was discovered to be broken while exploring the spec — real propagation of `context["auth"]` into the 21 active modules that currently bypass it by calling `requests` directly.

**Architecture:** All active modules funnel their HTTP calls through `scanner/core/http.py` (`get`/`post`), which already merges `context["auth"]` and gains rate limiting + optional evidence capture. A new `scanner/core/matchers.py` evaluates declarative conditions against an `HttpResult`, consumed by two pilot modules (`sqli`, `xss`) and the two new modules (`ssti`, `nosqli`). `Finding` gains `evidence_request`/`evidence_response`. SQLite gains a `triage_status` column plus a `PATCH /history/triage/<id>` endpoint. No change to `engine.py`'s orchestration — `context` already flows from `routes/scanner_engine.py` through every module untouched.

**Tech Stack:** Python 3.14, Flask 3.0, `requests` 2.31, `pytest` 8.0 + `pytest-mock` 3.12 (already in `requirements.txt` — no new dependencies).

**Spec:** [docs/superpowers/specs/2026-10-14-vulnscan-premium-hardening-design.md](../specs/2026-10-14-vulnscan-premium-hardening-design.md) §2 (Round 6). The spec's §2.4 scope was expanded during planning — see Task 6-11 below — after discovering 22 of 24 active modules never read `context["auth"]` at all, so the advertised "scan authentifié" feature silently no-ops for them. (Of those 22, `subdomain_enum.py` turned out on closer reading to make zero HTTP calls against the scanned target — only DNS lookups plus one call to the external `crt.sh` service, which must *not* carry auth — so it needs a regression test, not a migration; 21 modules are actually migrated.)

## Global Constraints

- Every HTTP call an active module makes must go through `scanner/core/http.py::get`/`post` — never `requests.get`/`requests.post` directly — so auth, rate limiting, and evidence capture apply uniformly (spec §2.1-2.4).
- `evidence_request`/`evidence_response`, when captured, must never contain a real `Authorization`, `Cookie`, or `Set-Cookie` value, or a `requests` `auth=(user, pass)` tuple in cleartext (spec §2.2, Global Constraint added during planning: Review Focus #2).
- Response body snippets in evidence are truncated to 4096 bytes (spec §2.2).
- SQLite migrations are additive only (`ALTER TABLE ... ADD COLUMN`), guarded to be idempotent — never `DROP`/`RENAME` (spec §2.3, §5).
- The crawler's own requests (`scanner/core/crawler.py`) and `subdomain_enum.py`'s call to the external `crt.sh` Certificate Transparency service are explicitly **out of scope** for the `http.py` migration: crawler already threads its own auth correctly, and sending the target's session cookie to a third-party service (`crt.sh`) would leak it. `subdomain_enum.py` makes no other HTTP call (its subdomain discovery is pure DNS via `socket.gethostbyname`), so it needs no migration at all — only a regression test pinning that `crt.sh` never receives auth (Task 9).
- No new runtime dependency is introduced (spec §1 non-objectifs).

## Review Focus

- **Time-based matcher false positive under target latency jitter.** A slow-but-not-vulnerable target could cross a fixed delay threshold on network noise alone. Task 12's tests must assert the matcher compares *delta vs. baseline*, not raw elapsed time.
- **Auth leakage through a non-header channel.** `requests`' `auth=(user, pass)` tuple (Basic Auth) is not a header and is missed by header-only redaction. Task 3 must scrub it from `evidence_request` explicitly, with a test proving it.
- **Triage endpoint called with an unknown `finding_id`.** A stale UI reference (finding already deleted, typo'd id) must return 404, not a false "success". Task 5's test must cover this.
- **SSTI false positive from re-fetching the baseline per probe.** If the baseline were re-fetched for every probe instead of once per scan, a page that isn't perfectly deterministic between requests (timestamp, nonce, counter) could make "value absent from baseline" look true by accident on one fetch and false on another, for reasons unrelated to the injected payload. Task 14 must test that the baseline is fetched exactly once per scan and reused for every probe, not re-fetched.
- **NoSQLi false positive from ordinary response variance.** A baseline vs. payload response that differ only because of unrelated non-determinism (not the injected operator) must not be flagged; Task 15's "ignores identical behavior" test must use a *status that's still an auth failure* with a body length within the 20% band, not an exact byte match, to prove the threshold isn't trivially met.

---

## Task 1: Declarative matcher engine

**Files:**
- Create: `backend/scanner/core/matchers.py`
- Test: `backend/tests/test_matchers.py`

**Interfaces:**
- Produces: `HttpResult(status: int, headers: dict, body: str, elapsed_ms: float = 0.0)` — dataclass
- Produces: `Matcher(type: str, part: str = "body", words: List[str] = [], regex: Optional[str] = None, status_codes: List[int] = [], min_delay_ms: Optional[float] = None, negative: bool = False)` — dataclass
- Produces: `evaluate_matcher(matcher: Matcher, result: HttpResult) -> bool`
- Produces: `evaluate(matchers: List[Matcher], condition: str, result: HttpResult) -> bool` — `condition` is `"and"` or `"or"`; empty `matchers` list returns `False`
- Produces: `matchers_from_dicts(raw: List[dict]) -> List[Matcher]` — builds `Matcher` objects from the `matchers` key of a payload-catalog JSON entry (keys map 1:1 to `Matcher` fields; missing keys use the dataclass defaults)

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_matchers.py
from scanner.core.matchers import HttpResult, Matcher, evaluate_matcher, evaluate, matchers_from_dicts

def _result(**overrides):
    base = dict(status=200, headers={}, body="", elapsed_ms=0.0)
    base.update(overrides)
    return HttpResult(**base)

def test_word_matcher_matches_substring_in_body():
    m = Matcher(type="word", part="body", words=["SQL syntax"])
    assert evaluate_matcher(m, _result(body="you have an error in your SQL syntax")) is True

def test_word_matcher_no_match():
    m = Matcher(type="word", part="body", words=["SQL syntax"])
    assert evaluate_matcher(m, _result(body="all good")) is False

def test_regex_matcher_matches():
    m = Matcher(type="regex", part="body", regex=r"uid=\d+\(\w+\)")
    assert evaluate_matcher(m, _result(body="output: uid=0(root) gid=0(root)")) is True

def test_status_matcher():
    m = Matcher(type="status", status_codes=[500, 502])
    assert evaluate_matcher(m, _result(status=500)) is True
    assert evaluate_matcher(m, _result(status=200)) is False

def test_time_matcher_min_delay():
    m = Matcher(type="time", min_delay_ms=3500)
    assert evaluate_matcher(m, _result(elapsed_ms=4200)) is True
    assert evaluate_matcher(m, _result(elapsed_ms=900)) is False

def test_word_matcher_on_header_part():
    m = Matcher(type="word", part="header", words=["nginx"])
    assert evaluate_matcher(m, _result(headers={"Server": "nginx/1.18"})) is True

def test_negative_matcher_inverts_result():
    m = Matcher(type="word", part="body", words=["login"], negative=True)
    assert evaluate_matcher(m, _result(body="welcome dashboard")) is True
    assert evaluate_matcher(m, _result(body="please login")) is False

def test_evaluate_and_requires_all_matchers():
    matchers = [Matcher(type="status", status_codes=[200]), Matcher(type="word", words=["ok"])]
    assert evaluate(matchers, "and", _result(status=200, body="ok")) is True
    assert evaluate(matchers, "and", _result(status=200, body="nope")) is False

def test_evaluate_or_requires_any_matcher():
    matchers = [Matcher(type="status", status_codes=[500]), Matcher(type="word", words=["ok"])]
    assert evaluate(matchers, "or", _result(status=200, body="ok")) is True
    assert evaluate(matchers, "or", _result(status=200, body="nope")) is False

def test_evaluate_empty_matchers_is_false():
    assert evaluate([], "and", _result()) is False

def test_matchers_from_dicts_builds_matcher_objects():
    raw = [{"type": "word", "part": "body", "words": ["x"]}, {"type": "status", "status_codes": [500]}]
    built = matchers_from_dicts(raw)
    assert len(built) == 2
    assert built[0].type == "word" and built[0].words == ["x"]
    assert built[1].status_codes == [500]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_matchers.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scanner.core.matchers'`

- [ ] **Step 3: Implement `matchers.py`**

`evaluate_matcher` dispatches on `matcher.type`: for `"word"`, substring-check each of `matcher.words` against `result.body` (if `part == "body"`) or against the joined `"k: v"` lines of `result.headers` (if `part == "header"`), case-insensitive, `any()` match; for `"regex"`, `re.search(matcher.regex, result.body, re.I)`; for `"status"`, `result.status in matcher.status_codes`; for `"time"`, `result.elapsed_ms >= matcher.min_delay_ms`. If `matcher.negative`, invert the computed boolean before returning. `evaluate` applies `all()`/`any()` over `[evaluate_matcher(m, result) for m in matchers]` depending on `condition`, returning `False` for an empty list regardless of condition. `matchers_from_dicts` does `[Matcher(**d) for d in raw]`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_matchers.py -v`
Expected: PASS (11 tests)

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/core/matchers.py backend/tests/test_matchers.py
git commit -m "feat(scanner): add declarative matcher engine

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 2: Finding gains evidence_request/evidence_response

**Files:**
- Modify: `backend/scanner/core/module_base.py:14-50` (the `Finding` dataclass and `to_dict`)
- Test: `backend/tests/test_modules.py` (extend `test_finding_to_dict_shape`, add one function)

**Interfaces:**
- Modifies: `Finding` — adds `evidence_request: Optional[Dict[str, Any]] = None` and `evidence_response: Optional[Dict[str, Any]] = None`, inserted right after the existing `evidence: str = ""` field
- Produces: `Finding.to_dict()` now includes `evidenceRequest` and `evidenceResponse` keys (camelCase, `None` when not set) — every later task that builds a `Finding` with captured evidence sets these two fields by name

- [ ] **Step 1: Write the failing test**

Add to `backend/tests/test_modules.py`:

```python
def test_finding_to_dict_includes_evidence_request_response_when_set():
    from scanner.core.module_base import Finding
    f = Finding(
        type="sqli", severity="critical", description="t", recommendation="t", url="http://a",
        evidence_request={"method": "GET", "url": "http://a", "headers": {}, "body": None},
        evidence_response={"status": 200, "headers": {}, "body_snippet": "ok", "elapsed_ms": 12.3},
    )
    d = f.to_dict()
    assert d["evidenceRequest"]["method"] == "GET"
    assert d["evidenceResponse"]["status"] == 200

def test_finding_to_dict_evidence_defaults_to_none():
    from scanner.core.module_base import Finding
    f = Finding(type="xss", severity="high", description="t", recommendation="t", url="http://a")
    d = f.to_dict()
    assert d["evidenceRequest"] is None
    assert d["evidenceResponse"] is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_modules.py -k evidence_request -v`
Expected: FAIL with `TypeError: __init__() got an unexpected keyword argument 'evidence_request'`

- [ ] **Step 3: Implement the field + serialization**

In the `Finding` dataclass, add the two fields after `evidence: str = ""`. In `to_dict()`, after the existing `cwe_id`/`owasp_id` handling, add:
```python
d["evidenceRequest"] = d.pop("evidence_request")
d["evidenceResponse"] = d.pop("evidence_response")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_modules.py -v`
Expected: PASS (all tests in the file, including the pre-existing ones)

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/core/module_base.py backend/tests/test_modules.py
git commit -m "feat(scanner): add evidence_request/evidence_response to Finding

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 3: HTTP evidence capture with redaction

**Files:**
- Modify: `backend/scanner/core/http.py` (whole file — add imports, capture helpers, extend `send`/`get`/`post`)
- Test: `backend/tests/test_http_client.py` (extend)

**Interfaces:**
- Consumes: nothing new (builds on the existing `_merged_kwargs`)
- Produces: `send(method, url, context=None, capture: bool = False, **kwargs)` — when `capture=False` (default), behavior and return type (`Optional[requests.Response]`) are unchanged from today; when `capture=True`, returns `(response_or_none, evidence_request_or_none, evidence_response_or_none)` — a 3-tuple
- Produces: `get(url, context=None, capture: bool = False, **kwargs)` / `post(url, context=None, capture: bool = False, **kwargs)` — same capture semantics, delegate to `send`
- Every later task that wants evidence calls `response, req_ev, resp_ev = http.get(url, context, capture=True, ...)` (or `http.post`)

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_http_client.py`:

```python
def test_send_without_capture_returns_plain_response(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={"Server": "nginx"}, text="ok")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    result = http.send("GET", "http://example.com/x")
    assert result is fake

def test_send_with_capture_returns_triple(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={"Server": "nginx"}, text="ok")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    response, req_ev, resp_ev = http.send("GET", "http://example.com/x", capture=True)
    assert response is fake
    assert req_ev["method"] == "GET" and req_ev["url"] == "http://example.com/x"
    assert resp_ev["status"] == 200 and resp_ev["body_snippet"] == "ok"

def test_capture_redacts_authorization_header(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"headers": {"Authorization": "Bearer secret-token"}}}
    _, req_ev, _ = http.send("GET", "http://example.com/x", context=ctx, capture=True)
    assert req_ev["headers"]["Authorization"] == "***"

def test_capture_redacts_cookie_header_and_set_cookie_response_header(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={"Set-Cookie": "session=abc123"}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"cookies": {"session": "abc123"}}}
    _, req_ev, resp_ev = http.send("GET", "http://example.com/x", context=ctx, capture=True,
                                    headers={"Cookie": "session=abc123"})
    assert req_ev["headers"]["Cookie"] == "***"
    assert resp_ev["headers"]["Set-Cookie"] == "***"

def test_capture_omits_basic_auth_tuple_from_evidence(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"basic": ("admin", "s3cr3t")}}
    _, req_ev, _ = http.send("GET", "http://example.com/x", context=ctx, capture=True)
    assert "s3cr3t" not in str(req_ev)
    assert "auth" not in req_ev

def test_capture_truncates_body_snippet_to_4096_bytes(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="A" * 10000)
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    _, _, resp_ev = http.send("GET", "http://example.com/x", capture=True)
    assert len(resp_ev["body_snippet"]) == 4096

def test_send_capture_on_network_error_returns_none_triple(mocker):
    from scanner.core import http
    import requests as requests_module
    mocker.patch("scanner.core.http.requests.request", side_effect=requests_module.exceptions.ConnectionError())
    result = http.send("GET", "http://example.com/x", capture=True)
    assert result == (None, None, None)

def test_get_and_post_pass_capture_through(mocker):
    from scanner.core import http
    fake = mocker.Mock(status_code=200, headers={}, text="ok")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    response, req_ev, resp_ev = http.get("http://example.com/x", capture=True)
    assert response is fake and req_ev["method"] == "GET"
    response2, req_ev2, resp_ev2 = http.post("http://example.com/x", capture=True, json={"a": 1})
    assert response2 is fake and req_ev2["method"] == "POST"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_http_client.py -v`
Expected: FAIL — `send()` has no `capture` parameter yet (`TypeError: send() got an unexpected keyword argument 'capture'`)

- [ ] **Step 3: Implement capture + redaction in `http.py`**

Add `MAX_BODY_SNIPPET = 4096` and `SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}` near the existing `DEFAULT_TIMEOUT`/`DEFAULT_UA` constants. Add:

```python
def _redact_headers(headers):
    return {k: ("***" if k.lower() in SENSITIVE_HEADERS else v) for k, v in (headers or {}).items()}

def _build_evidence(method, url, opts, response, elapsed_ms):
    req_ev = {
        "method": method.upper(),
        "url": url,
        "headers": _redact_headers(opts.get("headers")),
        "body": opts.get("data") if opts.get("data") is not None else opts.get("json"),
    }
    resp_ev = {
        "status": response.status_code,
        "headers": _redact_headers(dict(response.headers)),
        "body_snippet": (response.text or "")[:MAX_BODY_SNIPPET],
        "elapsed_ms": round(elapsed_ms, 1),
    }
    return req_ev, resp_ev
```

Note `opts` (the dict returned by `_merged_kwargs`) may contain an `"auth"` key (the Basic Auth tuple) — `_build_evidence` must not read or forward it, which the dict literal above already guarantees since it only reads `headers`/`data`/`json`.

Change `send`'s signature to `send(method, url, context=None, capture=False, **kwargs)`. Keep the existing try/except around `requests.request`, but time it with `time.monotonic()` before/after (add `import time` at the top of the file). On the `except` branch, `return (None, None, None) if capture else None`. On success, `if capture: return response, *_build_evidence(method, url, opts, response, elapsed_ms)`; else `return response` (unchanged). Update `get`/`post` to accept and forward `capture`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_http_client.py -v`
Expected: PASS (all tests, old and new)

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/core/http.py backend/tests/test_http_client.py
git commit -m "feat(scanner): capture redacted request/response evidence in http.send

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 4: Global per-host rate limiter + extension wiring

**Files:**
- Modify: `backend/scanner/core/http.py` (add `_throttle`, call it from `send`)
- Modify: `extension/src/background/service-worker.js:299-313` (`runActiveModules` — add `rate_limit_per_sec` to the context sent to `/scanner/run`)
- Test: `backend/tests/test_rate_limiter.py` (new)

**Interfaces:**
- Consumes: `context.get("rate_limit_per_sec")` — read inside `http.py`, defaulting to `10` when absent or falsy
- Produces: `send()` now sleeps as needed before each request so consecutive calls to the same hostname respect the configured rate — no new public function, this is internal to `send`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_rate_limiter.py
import time


def test_throttle_waits_between_calls_to_same_host(mocker):
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    sleep_mock = mocker.patch("scanner.core.http.time.sleep")
    # `send()` also reads time.monotonic() internally for its own elapsed_ms timing, so this
    # test does not try to count exact calls — it uses a shared mutable clock that always
    # returns the current instant, and advances it by exactly 0.02s between the two send()s.
    clock = {"t": 100.0}
    mocker.patch("scanner.core.http.time.monotonic", side_effect=lambda: clock["t"])

    http.send("GET", "http://a.test/one", context={"rate_limit_per_sec": 10})
    clock["t"] += 0.02  # only 20ms later — below the 100ms floor for 10 req/s
    http.send("GET", "http://a.test/two", context={"rate_limit_per_sec": 10})

    sleep_mock.assert_called_once()
    waited = sleep_mock.call_args[0][0]
    assert 0.07 < waited < 0.09  # ~0.1s floor minus the 0.02s already elapsed


def test_throttle_does_not_wait_for_different_hosts(mocker):
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    sleep_mock = mocker.patch("scanner.core.http.time.sleep")
    mocker.patch("scanner.core.http.time.monotonic", return_value=100.0)

    http.send("GET", "http://a.test/one", context={"rate_limit_per_sec": 10})
    http.send("GET", "http://b.test/one", context={"rate_limit_per_sec": 10})

    sleep_mock.assert_not_called()


def test_throttle_defaults_to_10_per_second_when_unconfigured(mocker):
    from scanner.core import http
    http._last_request_at.clear()
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fake)
    sleep_mock = mocker.patch("scanner.core.http.time.sleep")
    monotonic_values = iter([100.0, 100.0, 100.0, 100.0])
    mocker.patch("scanner.core.http.time.monotonic", side_effect=lambda: next(monotonic_values))

    http.send("GET", "http://c.test/one", context=None)
    http.send("GET", "http://c.test/two", context=None)

    sleep_mock.assert_called_once()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_rate_limiter.py -v`
Expected: FAIL — `AttributeError: module 'scanner.core.http' has no attribute '_last_request_at'`

- [ ] **Step 3: Implement `_throttle`**

Add `import threading` and `from urllib.parse import urlparse` to `http.py`. Add module-level state `_rate_lock = threading.Lock()` and `_last_request_at: Dict[str, float] = {}`. Add:

```python
def _throttle(url, context):
    rate = (context or {}).get("rate_limit_per_sec") or 10
    if rate <= 0:
        return
    min_interval = 1.0 / rate
    host = urlparse(url).hostname or ""
    with _rate_lock:
        now = time.monotonic()
        wait = min_interval - (now - _last_request_at.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last_request_at[host] = time.monotonic()
```

Call `_throttle(url, context)` as the first line inside `send()`, before the try/except.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_rate_limiter.py tests/test_http_client.py -v`
Expected: PASS (the Task 3 tests must still pass — they don't set `rate_limit_per_sec`, so `_throttle` runs with the default-10 path; since each of those tests starts with no prior entry for its particular test host, it never sleeps)

- [ ] **Step 5: Wire `requestsPerSecond` from the extension config into the scan context**

In `extension/src/background/service-worker.js`, inside `runActiveModules(cfg, url)` (around line 299-313, right before the `fetch(cfg.backendUrl + "/scanner/run", ...)` call), change the request body construction so the `context` object includes `rate_limit_per_sec: cfg.requestsPerSecond`:

```javascript
context: { ...(auth ? { auth } : {}), rate_limit_per_sec: cfg.requestsPerSecond },
```

- [ ] **Step 6: Verify the edit**

Run: `grep -n "rate_limit_per_sec" extension/src/background/service-worker.js`
Expected: one match, inside the `/scanner/run` request body construction in `runActiveModules`.

- [ ] **Step 7: Commit**

```bash
git add backend/scanner/core/http.py backend/tests/test_rate_limiter.py extension/src/background/service-worker.js
git commit -m "feat(scanner): add global per-host rate limiter, wire requestsPerSecond through

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 5: Persistent triage (confirmed / false positive)

**Files:**
- Modify: `backend/database/db.py` (migration in `init_db`, new `set_triage`)
- Modify: `backend/routes/history.py` (new `PATCH /triage/<finding_id>` route)
- Test: `backend/tests/test_triage.py` (new)

**Interfaces:**
- Produces: `database.db.set_triage(finding_id: str, status: str, note: Optional[str] = None) -> bool` — raises `ValueError` if `status` is not one of `"unreviewed"`, `"confirmed"`, `"false_positive"`; returns `True` if a row was updated, `False` if no finding with that id exists
- Produces: `PATCH /history/triage/<finding_id>` with JSON body `{"status": "...", "note": "..."?}` → `200 {"success": true}` on update, `404 {"error": "introuvable"}` when `set_triage` returns `False`, `400 {"error": "status invalide"}` when `status` is missing/invalid

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_triage.py
import pytest


def test_init_db_migration_adds_triage_columns_idempotently(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    dbmod.init_db()  # doit être idempotent, pas d'exception "duplicate column"
    with dbmod._connect() as conn:
        cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    assert "triage_status" in cols and "triage_note" in cols


def test_set_triage_updates_existing_finding(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    dbmod.save_scan({"id": "s1", "url": "http://h.test", "startedAt": 1,
                      "vulnerabilities": [{"id": "v1", "type": "xss", "severity": "high", "url": "u"}]})
    assert dbmod.set_triage("v1", "confirmed", "vérifié manuellement") is True
    with dbmod._connect() as conn:
        row = conn.execute("SELECT triage_status, triage_note FROM findings WHERE id = 'v1'").fetchone()
    assert row["triage_status"] == "confirmed"
    assert row["triage_note"] == "vérifié manuellement"


def test_set_triage_returns_false_for_unknown_id(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    assert dbmod.set_triage("does-not-exist", "confirmed") is False


def test_set_triage_rejects_invalid_status(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    with pytest.raises(ValueError):
        dbmod.set_triage("v1", "maybe")


def test_triage_endpoint_confirms_and_404s_on_unknown_id(monkeypatch, tmp_path):
    from database import db as dbmod
    monkeypatch.setattr(dbmod, "DB_PATH", str(tmp_path / "test.db"))
    dbmod.init_db()
    dbmod.save_scan({"id": "s1", "url": "http://h.test", "startedAt": 1,
                      "vulnerabilities": [{"id": "v1", "type": "xss", "severity": "high", "url": "u"}]})

    from flask import Flask
    from routes.history import history_bp
    app = Flask(__name__)
    app.register_blueprint(history_bp)
    client = app.test_client()

    ok = client.patch("/triage/v1", json={"status": "false_positive", "note": "page générique"})
    assert ok.status_code == 200 and ok.get_json()["success"] is True

    missing = client.patch("/triage/unknown-id", json={"status": "confirmed"})
    assert missing.status_code == 404

    bad = client.patch("/triage/v1", json={"status": "bogus"})
    assert bad.status_code == 400
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_triage.py -v`
Expected: FAIL — `AttributeError: module 'database.db' has no attribute 'set_triage'`

- [ ] **Step 3: Implement the migration and `set_triage` in `database/db.py`**

Inside `init_db()`, after the existing `conn.executescript(...)` call, add a column-presence check and conditional `ALTER TABLE`:

```python
cols = {row["name"] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
if "triage_status" not in cols:
    conn.execute("ALTER TABLE findings ADD COLUMN triage_status TEXT DEFAULT 'unreviewed'")
if "triage_note" not in cols:
    conn.execute("ALTER TABLE findings ADD COLUMN triage_note TEXT")
```

Add a module-level constant `TRIAGE_STATUSES = {"unreviewed", "confirmed", "false_positive"}` and:

```python
def set_triage(finding_id: str, status: str, note: Optional[str] = None) -> bool:
    if status not in TRIAGE_STATUSES:
        raise ValueError(f"status invalide : {status}")
    with _lock, _connect() as conn:
        c = conn.execute(
            "UPDATE findings SET triage_status = ?, triage_note = ? WHERE id = ?",
            (status, note, finding_id),
        )
        return c.rowcount > 0
```

- [ ] **Step 4: Implement the route in `routes/history.py`**

Add `set_triage` to the existing `from database.db import ...` line, and the TRIAGE_STATUSES import (or just inline the 3-value check). Add:

```python
@history_bp.route("/triage/<finding_id>", methods=["PATCH"])
def triage(finding_id):
    body = request.get_json(silent=True) or {}
    status = body.get("status")
    try:
        ok = set_triage(finding_id, status, body.get("note"))
    except ValueError:
        return jsonify({"error": "status invalide"}), 400
    if not ok:
        return jsonify({"error": "introuvable"}), 404
    return jsonify({"success": True})
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_triage.py -v`
Expected: PASS (5 tests)

- [ ] **Step 6: Commit**

```bash
git add backend/database/db.py backend/routes/history.py backend/tests/test_triage.py
git commit -m "feat(backend): add persistent finding triage (confirmed/false_positive)

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 6: Auth-propagation fix, batch 1 — establishes the migration pattern

**Why this task exists:** verified in the running code (not assumed) that `headers.py`, `cors_misconfig.py`, `info_disclosure.py`, `jwt_analyzer.py`, and `rate_limit.py` import `requests` directly and never read `context["auth"]` — so a scan configured with session cookies tests these modules **unauthenticated**, silently. This task fixes those 5 and defines the pattern the remaining batches (Tasks 7-11) repeat.

**Files:**
- Modify: `backend/scanner/modules/headers.py:12,48` — replace `import requests` and its one `requests.get(target, timeout=8, allow_redirects=True, ...)` call
- Modify: `backend/scanner/modules/cors_misconfig.py:13,35` — same, one call site
- Modify: `backend/scanner/modules/info_disclosure.py:10,45` — same, one call site
- Modify: `backend/scanner/modules/jwt_analyzer.py:14,46` — same, one call site
- Modify: `backend/scanner/modules/rate_limit.py:15,47` — same, one call site
- Modify: `backend/tests/conftest.py` — add a shared assertion helper
- Test: `backend/tests/test_auth_propagation.py` (new — used by this task and Tasks 7-11)

**Interfaces:**
- Consumes: `scanner.core.http.get`/`post` (Tasks 3-4)
- Produces (in `conftest.py`): `assert_module_propagates_auth(mocker, module_cls, target, extra_context=None)` — a pytest helper, not a fixture: patches `scanner.core.http.requests.request`, runs `module_cls().scan(target, {"auth": {"headers": {"Authorization": "Bearer AUTH-PROPAGATION-TEST"}}, **(extra_context or {})})`, and asserts at least one call reached `requests.request` with that header present. Every later batch task (7-11) calls this helper instead of redefining the mock setup.

**The migration pattern (apply identically in every call site below):**
1. Replace `import requests` with `from scanner.core import http`
2. Each `requests.get(url, **kwargs)` → `http.get(url, context, **kwargs)`; each `requests.post(url, **kwargs)` → `http.post(url, context, **kwargs)`. All existing kwargs (`timeout=`, `headers=`, `allow_redirects=`, `data=`, `json=`) are forwarded unchanged — `http.get`/`post` accept `**kwargs` exactly like `requests.get`/`post` do.
3. `context` is already the module's `scan(self, target, context)` parameter — no new parameter needed.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/conftest.py`:

```python
def assert_module_propagates_auth(mocker, module_cls, target, extra_context=None):
    """Échoue si `module_cls` n'appelle pas scanner.core.http (donc ne propage pas context['auth'])."""
    fake = mocker.Mock(status_code=200, headers={}, text="")
    mock_request = mocker.patch("scanner.core.http.requests.request", return_value=fake)
    ctx = {"auth": {"headers": {"Authorization": "Bearer AUTH-PROPAGATION-TEST"}}}
    if extra_context:
        ctx.update(extra_context)
    module_cls().scan(target, ctx)
    assert mock_request.called, f"{module_cls.__name__} n'a fait aucun appel via scanner.core.http"
    assert any(
        call.kwargs.get("headers", {}).get("Authorization") == "Bearer AUTH-PROPAGATION-TEST"
        for call in mock_request.call_args_list
    ), f"{module_cls.__name__} ne propage pas context['auth'] — appel direct à requests toujours en place ?"
```

Create `backend/tests/test_auth_propagation.py`:

```python
from tests.conftest import assert_module_propagates_auth


def test_headers_module_propagates_auth(mocker):
    from scanner.modules.headers import HeadersModule
    assert_module_propagates_auth(mocker, HeadersModule, "http://example.com/")


def test_cors_misconfig_module_propagates_auth(mocker):
    from scanner.modules.cors_misconfig import CorsMisconfigModule
    assert_module_propagates_auth(mocker, CorsMisconfigModule, "http://example.com/")


def test_info_disclosure_module_propagates_auth(mocker):
    from scanner.modules.info_disclosure import InfoDisclosureModule
    assert_module_propagates_auth(mocker, InfoDisclosureModule, "http://example.com/")


def test_jwt_analyzer_module_propagates_auth(mocker):
    from scanner.modules.jwt_analyzer import JwtAnalyzerModule
    assert_module_propagates_auth(mocker, JwtAnalyzerModule, "http://example.com/")


def test_rate_limit_module_propagates_auth(mocker):
    from scanner.modules.rate_limit import RateLimitModule
    assert_module_propagates_auth(mocker, RateLimitModule, "http://example.com/login")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_auth_propagation.py -v`
Expected: FAIL — each assertion fails with "n'a fait aucun appel via scanner.core.http" (modules still call `requests` directly)

- [ ] **Step 3: Apply the migration pattern to the 5 files**

Per the pattern above, in each of `headers.py`, `cors_misconfig.py`, `info_disclosure.py`, `jwt_analyzer.py`, `rate_limit.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS — both the new auth tests and the pre-existing module tests (which don't depend on which request function is used internally)

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/headers.py backend/scanner/modules/cors_misconfig.py backend/scanner/modules/info_disclosure.py backend/scanner/modules/jwt_analyzer.py backend/scanner/modules/rate_limit.py backend/tests/conftest.py backend/tests/test_auth_propagation.py
git commit -m "fix(scanner): propagate context[auth] in headers/cors/info-disclosure/jwt/rate-limit modules

These 5 modules called requests.get directly, silently ignoring any
configured session cookie or Bearer token.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 7: Auth-propagation fix, batch 2

**Files:**
- Modify: `backend/scanner/modules/form_fuzzer.py:20,149,152`
- Modify: `backend/scanner/modules/header_injection.py:18` + its 2 call sites (in `_fuzz_headers`, read during Task 3/6 exploration — baseline call and the per-header-payload call)
- Modify: `backend/scanner/modules/json_fuzzer.py:18,81,102`
- Modify: `backend/scanner/modules/param_discovery.py:21,46` + its second call site further down `scan()`
- Modify: `backend/scanner/modules/graphql.py:18` + its 5 call sites (`_discover_endpoints`'s candidate probe, `_test_endpoint`'s introspection/suggestion/batch/sqli-variable requests)
- Test: extend `backend/tests/test_auth_propagation.py`

**Interfaces:** same pattern and helper as Task 6.

- [ ] **Step 1: Write the failing tests**

Add to `backend/tests/test_auth_propagation.py`:

```python
def test_form_fuzzer_module_propagates_auth(mocker):
    from scanner.modules.form_fuzzer import FormFuzzerModule
    forms = [{"action": "http://example.com/comment", "method": "POST",
              "fields": [{"name": "body", "type": "text", "value": ""}], "id": ""}]
    assert_module_propagates_auth(mocker, FormFuzzerModule, "http://example.com/",
                                   extra_context={"crawled": {"forms": forms}})


def test_header_injection_module_propagates_auth(mocker):
    from scanner.modules.header_injection import HeaderInjectionModule
    assert_module_propagates_auth(mocker, HeaderInjectionModule, "http://example.com/")


def test_json_fuzzer_module_propagates_auth(mocker):
    from scanner.modules.json_fuzzer import JsonFuzzerModule
    assert_module_propagates_auth(mocker, JsonFuzzerModule, "http://example.com/api/items")


def test_param_discovery_module_propagates_auth(mocker):
    from scanner.modules.param_discovery import ParamDiscoveryModule
    assert_module_propagates_auth(mocker, ParamDiscoveryModule, "http://example.com/")


def test_graphql_module_propagates_auth(mocker):
    from scanner.modules.graphql import GraphQLModule
    assert_module_propagates_auth(mocker, GraphQLModule, "http://example.com/graphql")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_auth_propagation.py -k "form_fuzzer or header_injection or json_fuzzer or param_discovery or graphql" -v`
Expected: FAIL for all 5

- [ ] **Step 3: Apply the migration pattern**

Same as Task 6's pattern, across all listed call sites. `json_fuzzer.py` keeps its `requests.post(url, json=...)` shape, just swapped for `http.post(url, context, json=...)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/form_fuzzer.py backend/scanner/modules/header_injection.py backend/scanner/modules/json_fuzzer.py backend/scanner/modules/param_discovery.py backend/scanner/modules/graphql.py backend/tests/test_auth_propagation.py
git commit -m "fix(scanner): propagate context[auth] in form-fuzzer/header-injection/json-fuzzer/param-discovery/graphql

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 8: Auth-propagation fix, batch 3

**Files:**
- Modify: `backend/scanner/modules/file_exposure.py:19,63`
- Modify: `backend/scanner/modules/dir_bruteforce.py:12,39,60` (keep its existing 5 req/s throttle logic untouched — it's independent of the new global rate limiter in Task 4, which now also applies as a floor once it calls `http.get`)
- Modify: `backend/scanner/modules/tech_fingerprint.py:17,71`
- Modify: `backend/scanner/modules/waf_detect.py:15,37,47`
- Test: extend `backend/tests/test_auth_propagation.py`

**Interfaces:** same pattern and helper as Task 6.

- [ ] **Step 1: Write the failing tests**

```python
def test_file_exposure_module_propagates_auth(mocker):
    from scanner.modules.file_exposure import FileExposureModule
    assert_module_propagates_auth(mocker, FileExposureModule, "http://example.com/")


def test_dir_bruteforce_module_propagates_auth(mocker):
    from scanner.modules.dir_bruteforce import DirBruteforceModule
    assert_module_propagates_auth(mocker, DirBruteforceModule, "http://example.com/")


def test_tech_fingerprint_module_propagates_auth(mocker):
    from scanner.modules.tech_fingerprint import TechFingerprintModule
    assert_module_propagates_auth(mocker, TechFingerprintModule, "http://example.com/")


def test_waf_detect_module_propagates_auth(mocker):
    from scanner.modules.waf_detect import WafDetectModule
    assert_module_propagates_auth(mocker, WafDetectModule, "http://example.com/")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_auth_propagation.py -k "file_exposure or dir_bruteforce or tech_fingerprint or waf_detect" -v`
Expected: FAIL for all 4

- [ ] **Step 3: Apply the migration pattern**

Same as Task 6. For `dir_bruteforce.py`, only the two `requests.get(...)` calls change to `http.get(..., context, ...)` — its own `time.sleep(1/5)`-style per-request throttle (read earlier while exploring the spec) stays exactly as-is; it will now run on top of the Task 4 global limiter, which only raises the floor to "at least 10/s," never lowering below what `dir_bruteforce` already enforces at 5/s.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/file_exposure.py backend/scanner/modules/dir_bruteforce.py backend/scanner/modules/tech_fingerprint.py backend/scanner/modules/waf_detect.py backend/tests/test_auth_propagation.py
git commit -m "fix(scanner): propagate context[auth] in file-exposure/dir-bruteforce/tech-fingerprint/waf-detect

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 9: race_conditions simplification + subdomain_enum regression guard

Unlike every other module in this round, `subdomain_enum.py` turned out on
full read-through to make **no HTTP call against the scanned target at all**
— its subdomain discovery is pure DNS (`socket.gethostbyname`), and its only
network call is to the external `crt.sh` Certificate Transparency service,
which must *not* carry the target's auth. There is nothing to migrate there;
it only needs a test pinning that correct (already-true) behavior so a
future change can't accidentally start leaking auth to a third party.

**Files:**
- Modify: `backend/scanner/modules/race_conditions.py:24,84,93` — replace its hand-rolled `cookies = auth.get("cookies", {}); headers = {...}; headers.update(auth.get("headers", {}))` (lines 78-80) with a direct `http.post(action, context, data=data, timeout=8)` call. `_test_race` currently only receives `auth` (extracted once in `scan()` at line 69), not the full `context` — change its signature from `_test_race(self, form, auth)` to `_test_race(self, form, context)`, update the one call site in `scan()` (`findings.extend(self._test_race(form, auth))` → `findings.extend(self._test_race(form, context))`), and delete the manual cookie/header construction entirely since `http.post` already reads `context["auth"]` itself
- Test: extend `backend/tests/test_auth_propagation.py` (race_conditions migration test + the subdomain_enum regression guard — no change needed to `subdomain_enum.py` itself)

**Interfaces:** same pattern and helper as Task 6, for `race_conditions.py` only.

- [ ] **Step 1: Write the failing tests**

```python
def test_race_conditions_module_propagates_auth(mocker):
    from scanner.modules.race_conditions import RaceConditionsModule
    forms = [{"action": "http://example.com/vote", "method": "POST",
              "fields": [{"name": "choice", "type": "text", "value": "1"}], "id": ""}]
    assert_module_propagates_auth(mocker, RaceConditionsModule, "http://example.com/",
                                   extra_context={"crawled": {"forms": forms}})


def test_subdomain_enum_never_sends_auth_header_to_crtsh(mocker):
    """subdomain_enum ne passe par scanner.core.http pour rien (aucun HTTP vers la cible) ;
    son unique appel réseau (crt.sh, service tiers) ne doit jamais recevoir le Bearer/cookie
    de la cible — comportement déjà correct aujourd'hui, ce test le fige."""
    from scanner.modules.subdomain_enum import SubdomainEnumModule
    mocker.patch("socket.gethostbyname", side_effect=OSError("no DNS in tests"))
    fake = mocker.Mock(ok=True, json=lambda: [])
    mock_via_http_module = mocker.patch("scanner.core.http.requests.request")
    mock_crtsh = mocker.patch("scanner.modules.subdomain_enum.requests.get", return_value=fake)
    ctx = {"auth": {"headers": {"Authorization": "Bearer SHOULD-NOT-LEAK"}}}
    SubdomainEnumModule().scan("http://example.com/", ctx)
    mock_via_http_module.assert_not_called()
    assert mock_crtsh.called
    assert "Authorization" not in (mock_crtsh.call_args.kwargs.get("headers") or {})
```

- [ ] **Step 2: Run tests to verify they fail/pass as expected**

Run: `cd backend && pytest tests/test_auth_propagation.py -k "race_conditions or subdomain_enum" -v`
Expected: `test_race_conditions_module_propagates_auth` FAILs (migration not done yet). `test_subdomain_enum_never_sends_auth_header_to_crtsh` already PASSes — it documents existing-correct behavior, not a fix; keep it as a regression guard.

- [ ] **Step 3: Apply the migration to `race_conditions.py` only**

Remove `import requests`, add `from scanner.core import http`; change `scan()`'s call `self._test_race(form, auth)` to `self._test_race(form, context)`; rewrite `_test_race` to drop the manual `cookies`/`headers` construction and call `http.post(action, context, data=data, timeout=8)` for both the solo request and inside `_one_request`. Do not touch `subdomain_enum.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/race_conditions.py backend/tests/test_auth_propagation.py
git commit -m "fix(scanner): simplify race-conditions auth handling via http.post; pin subdomain-enum/crt.sh isolation

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 10: Auth-propagation + evidence capture, batch A (lfi, ssrf, xxe)

These 3 are in the spec's original evidence-capture list (§2.2) — they get both the auth fix and `capture=True` on their *confirming* request only.

**Files:**
- Modify: `backend/scanner/modules/lfi.py:15` + both call sites (line 58 baseline, line 88 confirming payload request)
- Modify: `backend/scanner/modules/ssrf.py:16` + call sites (line 57 baseline, line 73 OOB probe, line 113 confirming payload request)
- Modify: `backend/scanner/modules/xxe.py:14,45`
- Test: extend `backend/tests/test_auth_propagation.py`; new assertions in `backend/tests/test_modules.py` for evidence presence

**Interfaces:** auth pattern per Task 6; additionally each module's **confirmed** `Finding` now sets `evidence_request`/`evidence_response` from the `capture=True` call that confirmed it.

- [ ] **Step 1: Write the failing tests**

Add to `test_auth_propagation.py`:
```python
def test_lfi_module_propagates_auth(mocker):
    from scanner.modules.lfi import LfiModule
    assert_module_propagates_auth(mocker, LfiModule, "http://example.com/?file=a")


def test_ssrf_module_propagates_auth(mocker):
    from scanner.modules.ssrf import SsrfModule
    mocker.patch("scanner.core.oob.OOBCanary.new").return_value.wait_for_hit.return_value = False
    assert_module_propagates_auth(mocker, SsrfModule, "http://example.com/?url=http://x")


def test_xxe_module_propagates_auth(mocker):
    from scanner.modules.xxe import XxeModule
    assert_module_propagates_auth(mocker, XxeModule, "http://example.com/api/xml")
```

Add to `test_modules.py`:
```python
def test_lfi_confirmed_finding_has_evidence_request_response(mocker):
    from scanner.modules.lfi import LfiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="nothing interesting")
    confirming = mocker.Mock(status_code=200, headers={}, text="root:x:0:0:root:/root:/bin/bash")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 20)
    findings = LfiModule().scan("http://example.com/?file=a", {})
    confirmed = [f for f in findings if f.severity == "critical"]
    assert confirmed, "aucune LFI confirmée avec une réponse contenant /etc/passwd"
    assert confirmed[0].evidence_request is not None
    assert confirmed[0].evidence_response["body_snippet"].startswith("root:x:0:0")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -k "lfi or ssrf or xxe" -v`
Expected: FAIL (no auth propagation, no evidence fields set)

- [ ] **Step 3: Apply auth migration + capture on the confirming call**

For each module, migrate every call site to `http.get`/`http.post` per the Task 6 pattern. On the specific call that, once matched against its existing signature regex, produces a `Finding`, add `capture=True` and destructure `response, req_ev, resp_ev = http.get(...)` (or the module's existing variable name in place of `response`); pass `evidence_request=req_ev, evidence_response=resp_ev` into that `Finding(...)` constructor call. Baseline/probe-only calls (that never directly produce a `Finding`) keep `capture=False` (the default — no change needed).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/lfi.py backend/scanner/modules/ssrf.py backend/scanner/modules/xxe.py backend/tests/test_auth_propagation.py backend/tests/test_modules.py
git commit -m "fix(scanner): propagate auth + capture evidence in lfi/ssrf/xxe

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 11: Auth-propagation + evidence capture, batch B (command_injection, idor, open_redirect)

**Files:**
- Modify: `backend/scanner/modules/command_injection.py:16,60`
- Modify: `backend/scanner/modules/idor.py:16` + call sites (line 41 baseline, line 62 confirming)
- Modify: `backend/scanner/modules/open_redirect.py:12,49`
- Test: extend `backend/tests/test_auth_propagation.py` and `backend/tests/test_modules.py`

**Interfaces:** identical to Task 10's pattern, applied to these 3 modules.

- [ ] **Step 1: Write the failing tests**

```python
# test_auth_propagation.py
def test_command_injection_module_propagates_auth(mocker):
    from scanner.modules.command_injection import CommandInjectionModule
    assert_module_propagates_auth(mocker, CommandInjectionModule, "http://example.com/?cmd=ping")


def test_idor_module_propagates_auth(mocker):
    from scanner.modules.idor import IdorModule
    assert_module_propagates_auth(mocker, IdorModule, "http://example.com/?id=5")


def test_open_redirect_module_propagates_auth(mocker):
    from scanner.modules.open_redirect import OpenRedirectModule
    assert_module_propagates_auth(mocker, OpenRedirectModule, "http://example.com/?next=/home")
```

```python
# test_modules.py
def test_command_injection_confirmed_finding_has_evidence(mocker):
    from scanner.modules.command_injection import CommandInjectionModule
    confirming = mocker.Mock(status_code=200, headers={}, text="uid=0(root) gid=0(root)")
    mocker.patch("scanner.core.http.requests.request", return_value=confirming)
    findings = CommandInjectionModule().scan("http://example.com/?cmd=ping", {})
    assert findings and findings[0].evidence_request is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -k "command_injection or idor or open_redirect" -v`
Expected: FAIL

- [ ] **Step 3: Apply auth migration + capture on the confirming call**

Same approach as Task 10, Step 3.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS — and this is the last auth-propagation batch, so also run: `cd backend && pytest tests/ -v` and confirm all 21 migrated modules are covered (21 `test_*_propagates_auth` functions across Tasks 6-11, plus `subdomain_enum`'s regression guard in Task 9 and `sqli`/`xss` covered in Tasks 12-13 below — 24 active modules total, matching the 24 found importing `requests` directly before this round)

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/command_injection.py backend/scanner/modules/idor.py backend/scanner/modules/open_redirect.py backend/tests/test_auth_propagation.py backend/tests/test_modules.py
git commit -m "fix(scanner): propagate auth + capture evidence in command-injection/idor/open-redirect

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 12: SQLi pilot — migrate to http.py, matcher-based time confirmation, evidence capture

**Files:**
- Modify: `backend/scanner/modules/sqli.py` (whole file: imports, `_timed_fetch`/`_fetch_with_param` helpers, the time-based loop in `scan()`)
- Test: extend `backend/tests/test_auth_propagation.py`; add to `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `scanner.core.matchers.{HttpResult, Matcher, evaluate}` (Task 1), `scanner.core.http.get` with `capture=True` (Task 3)
- Produces: no new public interface — `sqli.py`'s time-based blind detection now goes through the matcher engine internally

- [ ] **Step 1: Write the failing tests**

```python
# test_auth_propagation.py
def test_sqli_module_propagates_auth(mocker):
    from scanner.modules.sqli import SqliModule
    assert_module_propagates_auth(mocker, SqliModule, "http://example.com/?id=5")
```

```python
# test_modules.py
def test_sqli_time_based_uses_matcher_and_captures_evidence(mocker):
    from scanner.modules.sqli import SqliModule
    fast = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fast)
    mocker.patch("scanner.core.http.time.sleep")  # désactive le rate-limiter réel pour ce test
    # sqli.py mesure ses propres deltas via son `import time` (time.time()), pas via http.py.
    # _timed_fetch lit time.time() 2 fois (avant/après) par appel : base_time_1, base_time_2,
    # puis 1 fois pour le 1er payload de TIME_PAYLOADS (qui confirme et interrompt la boucle) :
    #   base_time_1: t0=0.0, t1=0.05   -> 0.05s
    #   base_time_2: t0=1.0, t1=1.05   -> 0.05s  => baseline = max(...) = 0.05
    #   1er payload: t0=2.0, t1=6.6    -> 4.6s   => delta = 4.6 - 0.05 = 4.55 >= 3.5 -> confirmé
    time_values = iter([0.0, 0.05, 1.0, 1.05, 2.0, 6.6])
    mocker.patch("scanner.modules.sqli.time.time", side_effect=lambda: next(time_values))

    findings = SqliModule().scan("http://example.com/?id=5", {})
    time_based = [f for f in findings if "time-based" in (f.title or "").lower()]
    assert time_based, "aucune SQLi time-based détectée malgré un delta de 4.55s"
    assert time_based[0].evidence_request is not None
    assert time_based[0].evidence_response is not None


def test_sqli_time_based_does_not_false_positive_on_network_jitter(mocker):
    from scanner.modules.sqli import SqliModule
    fast = mocker.Mock(status_code=200, headers={}, text="")
    mocker.patch("scanner.core.http.requests.request", return_value=fast)
    mocker.patch("scanner.core.http.time.sleep")
    # Baseline déjà lente (0.4s) ; chacun des 4 TIME_PAYLOADS n'ajoute que 0.3s de plus
    # (delta=0.3 < 3.5 à chaque fois) -> aucune confirmation, la boucle va jusqu'au bout.
    time_values = iter([
        0.0, 0.4,   # base_time_1 = 0.4s
        1.0, 1.4,   # base_time_2 = 0.4s  => baseline = 0.4
        2.0, 2.7,   # payload 1 : 0.7s, delta=0.3
        3.0, 3.7,   # payload 2 : 0.7s, delta=0.3
        4.0, 4.7,   # payload 3 : 0.7s, delta=0.3
        5.0, 5.7,   # payload 4 : 0.7s, delta=0.3
    ])
    mocker.patch("scanner.modules.sqli.time.time", side_effect=lambda: next(time_values))

    findings = SqliModule().scan("http://example.com/?id=5", {})
    assert not [f for f in findings if "time-based" in (f.title or "").lower()]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -k sqli -v`
Expected: FAIL (module still calls `requests` directly; no matcher use to assert against, but the auth test fails outright)

- [ ] **Step 3: Migrate `sqli.py`**

Replace `import requests` with `from scanner.core import http` and `from scanner.core.matchers import HttpResult, Matcher, evaluate`. In `_timed_fetch` and `_fetch_with_param`, swap `requests.get(...)` for `http.get(..., context, ...)` — both helpers need a new `context` parameter, threaded from `scan()`'s existing `context` argument through their call sites. In the time-based loop (the `for payload, dbms, sleep_s in self.TIME_PAYLOADS:` block), after computing `delta = t - baseline`, build `result = HttpResult(status=0, headers={}, body="", elapsed_ms=delta * 1000)` and replace the `if delta >= self.TIME_THRESHOLD:` check with `if evaluate([Matcher(type="time", min_delay_ms=self.TIME_THRESHOLD * 1000)], "and", result):`. For evidence: change the final confirming fetch (the one whose delta crosses the threshold) to use `http.get(..., context, capture=True, ...)` instead of the timing-only helper, so the `Finding` construction can pass `evidence_request=req_ev, evidence_response=resp_ev` (this means re-issuing one extra request specifically to capture evidence once a timing confirmation is found — acceptable since it only happens on confirmed findings, consistent with the spec's "requête de confirmation finale uniquement").

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/sqli.py backend/tests/test_auth_propagation.py backend/tests/test_modules.py
git commit -m "feat(scanner): migrate sqli time-based detection to matcher engine, add evidence capture

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 13: XSS pilot — migrate to http.py, matcher-based reflection check, evidence capture

**Files:**
- Modify: `backend/scanner/modules/xss.py` (whole file: imports, the marker-reflection check in `scan()`)
- Test: extend `backend/tests/test_auth_propagation.py`; add to `backend/tests/test_modules.py`

**Interfaces:**
- Consumes: `scanner.core.matchers.{HttpResult, Matcher, evaluate}`, `scanner.core.http.get` with `capture=True`
- Produces: no new public interface — the reflection check (`if marker not in body`) becomes a declarative word matcher; behavior and safety profile (still a harmless marker, never the real payload) are unchanged

- [ ] **Step 1: Write the failing tests**

```python
# test_auth_propagation.py
def test_xss_module_propagates_auth(mocker):
    from scanner.modules.xss import XssModule
    assert_module_propagates_auth(mocker, XssModule, "http://example.com/?q=hi")
```

```python
# test_modules.py
def test_xss_reflection_uses_matcher_and_captures_evidence(mocker):
    from scanner.modules.xss import XssModule
    import scanner.modules.xss as xss_mod

    # xss.py génère son propre marqueur aléatoire et l'injecte comme valeur du paramètre ;
    # on simule un serveur qui réfléchit systématiquement la valeur du param dans le body,
    # et on patche http.get directement pour contrôler précisément ce que scan() reçoit.
    def fake_get(url, ctx, capture=False, **kw):
        reflected_value = url.split("=")[-1]
        response = mocker.Mock(status_code=200, headers={}, text=f"<p>{reflected_value}</p>")
        if capture:
            req_ev = {"method": "GET", "url": url, "headers": {}, "body": None}
            resp_ev = {"status": 200, "headers": {}, "body_snippet": response.text, "elapsed_ms": 5.0}
            return response, req_ev, resp_ev
        return response

    mocker.patch.object(xss_mod.http, "get", side_effect=fake_get)
    findings = XssModule().scan("http://example.com/?q=hi", {})
    assert findings
    assert findings[0].evidence_request is not None
    assert findings[0].evidence_response is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -k xss -v`
Expected: FAIL

- [ ] **Step 3: Migrate `xss.py`**

Replace `import requests` with `from scanner.core import http` and `from scanner.core.matchers import HttpResult, Matcher, evaluate`. Change the detection call to `response, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8, headers={"User-Agent": "VulnScan/1.2"})`; guard `if response is None: continue`; set `body = response.text`. Replace `if marker not in body: continue` with:
```python
result = HttpResult(status=response.status_code, headers=dict(response.headers), body=body)
if not evaluate([Matcher(type="word", part="body", words=[marker])], "and", result):
    continue
```
Pass `evidence_request=req_ev, evidence_response=resp_ev` into the `Finding(...)` call.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_auth_propagation.py tests/test_modules.py -v`
Expected: PASS — and this completes auth propagation + matcher-pilot coverage for all 24 pre-existing active modules; run `cd backend && pytest tests/ -v` for the full suite green.

- [ ] **Step 5: Commit**

```bash
git add backend/scanner/modules/xss.py backend/tests/test_auth_propagation.py backend/tests/test_modules.py
git commit -m "feat(scanner): migrate xss reflection check to matcher engine, add evidence capture

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 14: New module — Server-Side Template Injection (SSTI)

**Files:**
- Create: `backend/scanner/modules/ssti.py`
- Modify: `extension/src/utils/taxonomy.js` — add a `"ssti"` entry to `TAXONOMY` so the existing (pre-Round-7) UI doesn't show a raw `ssti` type string
- Test: `backend/tests/test_ssti.py` (new)

**Interfaces:**
- Produces: `SstiModule(ScannerModule)` with `name = "ssti"`, `category = "injection"`, `default_enabled = False`
- Consumes: `scanner.core.http.get` (capture on confirmation), `scanner.core.matchers` (not strictly required for this module's simple substring check, but kept consistent — see Step 3)

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_ssti.py
def test_ssti_confirms_jinja2_when_calculation_reflected(mocker):
    from scanner.modules.ssti import SstiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="<p>hello</p>")
    confirming = mocker.Mock(status_code=200, headers={}, text="<p>result: 49</p>")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 10)
    findings = SstiModule().scan("http://example.com/?name=hi", {})
    assert findings and findings[0].type == "ssti" and findings[0].severity == "critical"
    assert findings[0].evidence_request is not None


def test_ssti_ignores_when_expected_value_already_in_baseline(mocker):
    """Si la baseline contient déjà '49' (ex: une page qui affiche un âge), pas de faux positif."""
    from scanner.modules.ssti import SstiModule
    baseline = mocker.Mock(status_code=200, headers={}, text="<p>Age: 49</p>")
    confirming = mocker.Mock(status_code=200, headers={}, text="<p>Age: 49</p>")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [confirming] * 10)
    findings = SstiModule().scan("http://example.com/?name=hi", {})
    assert findings == []


def test_ssti_fetches_baseline_exactly_once_regardless_of_probe_count(mocker):
    """La baseline est récupérée une seule fois puis réutilisée pour les 4 sondes du même
    paramètre — jamais re-fetchée à chaque essai. Si elle l'était, une page qui n'est pas
    parfaitement déterministe d'une requête à l'autre (timestamp, nonce, compteur) pourrait
    faire croire à tort que '49' est absent de "la" baseline alors qu'il ne l'était que de
    CETTE requête-ci — un seul fetch, comparé à toutes les sondes, évite ce piège."""
    from scanner.modules.ssti import SstiModule
    import scanner.modules.ssti as ssti_mod
    response = mocker.Mock(status_code=200, headers={}, text="<p>hello</p>")

    def fake_get(url, ctx, capture=False, **kw):
        if capture:
            req_ev = {"method": "GET", "url": url, "headers": {}, "body": None}
            resp_ev = {"status": 200, "headers": {}, "body_snippet": "hello", "elapsed_ms": 1.0}
            return response, req_ev, resp_ev
        return response

    mock_get = mocker.patch.object(ssti_mod.http, "get", side_effect=fake_get)
    SstiModule().scan("http://example.com/?name=hi", {})
    # 1 baseline (capture=False, implicite) + 4 sondes (capture=True, une par PROBES) = 5 appels
    assert mock_get.call_count == 5
    assert mock_get.call_args_list[0].kwargs.get("capture", False) is False


def test_ssti_skips_target_with_no_params():
    from scanner.modules.ssti import SstiModule
    assert SstiModule().scan("http://example.com/", {}) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_ssti.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scanner.modules.ssti'`

- [ ] **Step 3: Implement `ssti.py`**

```python
from __future__ import annotations
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
import re

from scanner.core.module_base import ScannerModule, Finding
from scanner.core import http


class SstiModule(ScannerModule):
    name = "ssti"
    category = "injection"
    title = "Server-Side Template Injection (SSTI)"
    description = "Injecte des expressions de calcul dans les paramètres GET pour détecter l'évaluation côté serveur (Jinja2/Twig/Freemarker/Thymeleaf)."
    default_enabled = False

    SUSPECT_PARAMS = {"name", "search", "q", "query", "page", "template", "view",
                      "title", "message", "comment", "text", "content"}

    PROBES = [
        ("{{7*7}}", "Jinja2/Twig", "49"),
        ("${7*7}",  "Freemarker/Velocity", "49"),
        ("#{7*7}",  "Thymeleaf (SpEL)", "49"),
        ("*{7*7}",  "Thymeleaf (alt)", "49"),
    ]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        if not re.match(r"^https?://", target):
            return []
        parsed = urlparse(target)
        params = dict(parse_qsl(parsed.query))
        if not params:
            return []

        findings: List[Finding] = []
        r_base = http.get(target, context, timeout=8)
        if r_base is None:
            return []
        baseline_body = r_base.text

        for param_name, base_value in params.items():
            if param_name.lower() not in self.SUSPECT_PARAMS:
                continue
            for payload, engine, expected in self.PROBES:
                new_params = dict(params)
                new_params[param_name] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                response, req_ev, resp_ev = http.get(test_url, context, capture=True, timeout=8)
                if response is None:
                    continue
                if expected in response.text and expected not in baseline_body:
                    findings.append(Finding(
                        type="ssti", severity="critical",
                        title=f"SSTI confirmée ({engine})",
                        description=(
                            f"Le paramètre '{param_name}' évalue '{payload}' côté serveur : "
                            f"'{expected}' apparaît dans la réponse et était absent de la baseline."
                        ),
                        recommendation=(
                            "Ne jamais passer d'entrée utilisateur directement à un moteur de template. "
                            "Utiliser le sandboxing du moteur (Jinja2 SandboxedEnvironment) ou séparer "
                            "strictement template et données."
                        ),
                        url=target, parameter=param_name, payload=payload,
                        evidence=f"'{expected}' obtenu, absent de la baseline",
                        confidence=90, cwe_id="CWE-1336", owasp_id="A03:2021",
                        cvss_base=9.8,
                        detection_method="ssti-arithmetic-probe",
                        source="module:ssti",
                        evidence_request=req_ev, evidence_response=resp_ev,
                    ))
                    break
        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_ssti.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Add the taxonomy entry**

In `extension/src/utils/taxonomy.js`, add to the `TAXONOMY` object (alongside `"xss"`, `"sqli"`, etc.):
```javascript
"ssti": {
  title: "Server-Side Template Injection",
  owasp: { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  cwe:   { id: "CWE-1336", name: "Improper Neutralization of Special Elements Used in a Template Engine",
           url: "https://cwe.mitre.org/data/definitions/1336.html" },
  cvssBase: 9.8,
  impact: "Exécution de code arbitraire côté serveur dans la plupart des cas — équivalent fonctionnel d'un RCE.",
  references: [
    { label: "PortSwigger SSTI", url: "https://portswigger.net/web-security/server-side-template-injection" },
  ],
},
```

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/modules/ssti.py backend/tests/test_ssti.py extension/src/utils/taxonomy.js
git commit -m "feat(scanner): add SSTI detection module

VulnScan previously exposed a testSSTI toggle in the extension's config
with no backend module ever implementing it.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Task 15: New module — NoSQL Injection (JSON endpoints)

**Files:**
- Create: `backend/scanner/modules/nosqli.py`
- Modify: `extension/src/utils/taxonomy.js` — add a `"nosqli"` entry
- Test: `backend/tests/test_nosqli.py` (new)

**Interfaces:**
- Produces: `NoSqliModule(ScannerModule)` with `name = "nosqli"`, `category = "injection"`, `default_enabled = False`
- Consumes: `scanner.core.http.post` (capture on confirmation), `context["crawled"]["api_endpoints"]`

- [ ] **Step 1: Write the failing tests**

```python
# backend/tests/test_nosqli.py
def test_nosqli_detects_auth_bypass_via_status_change(mocker):
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=401, headers={}, text="invalid credentials")
    bypass = mocker.Mock(status_code=200, headers={}, text="welcome back")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [bypass] * 10)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/login"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings and findings[0].type == "nosqli" and findings[0].severity == "critical"
    assert findings[0].evidence_request is not None


def test_nosqli_detects_data_leak_via_body_growth(mocker):
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=200, headers={}, text="{}")  # ~2 bytes
    leak = mocker.Mock(status_code=200, headers={}, text="{" + '"user":"a",' * 50 + "}")  # much bigger
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [leak] * 10)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/search"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings


def test_nosqli_ignores_when_behavior_matches_baseline(mocker):
    """Même statut (toujours 401) et taille de corps dans la même bande (<20% d'écart) -> pas de finding."""
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=401, headers={}, text="invalid credentials, try again")
    same = mocker.Mock(status_code=401, headers={}, text="invalid credentials, retry please")
    mocker.patch("scanner.core.http.requests.request", side_effect=[baseline] + [same] * 10)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/login"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings == []


def test_nosqli_skips_endpoint_when_baseline_is_404(mocker):
    from scanner.modules.nosqli import NoSqliModule
    baseline = mocker.Mock(status_code=404, headers={}, text="not found")
    mock_request = mocker.patch("scanner.core.http.requests.request", return_value=baseline)
    ctx = {"crawled": {"api_endpoints": ["http://example.com/api/missing"]}}
    findings = NoSqliModule().scan("http://example.com/", ctx)
    assert findings == []
    assert mock_request.call_count == 1  # une seule requête : la baseline, puis on abandonne l'endpoint


def test_nosqli_returns_empty_without_api_endpoints():
    from scanner.modules.nosqli import NoSqliModule
    assert NoSqliModule().scan("http://example.com/", {}) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && pytest tests/test_nosqli.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'scanner.modules.nosqli'`

- [ ] **Step 3: Implement `nosqli.py`**

```python
from __future__ import annotations
from typing import List, Dict, Any
import json
import secrets

from scanner.core.module_base import ScannerModule, Finding
from scanner.core import http


class NoSqliModule(ScannerModule):
    name = "nosqli"
    category = "injection"
    title = "NoSQL Injection"
    description = "Injecte des opérateurs MongoDB dans les endpoints JSON découverts et compare le comportement à une baseline (bypass d'auth / fuite de données)."
    default_enabled = False

    MAX_ENDPOINTS = 5
    BODY_GROWTH_THRESHOLD = 1.2  # +20%
    OPERATOR_PAYLOADS: List[Any] = [{"$gt": ""}, {"$ne": None}, "';return true;//"]

    def scan(self, target: str, context: Dict[str, Any]) -> List[Finding]:
        endpoints = (context.get("crawled") or {}).get("api_endpoints", [])[:self.MAX_ENDPOINTS]
        findings: List[Finding] = []
        for url in endpoints:
            findings.extend(self._test_endpoint(url, context))
        return findings

    def _test_endpoint(self, url: str, context: Dict[str, Any]) -> List[Finding]:
        baseline_body = {"username": "vulnscan_probe", "password": "wrong_pw_" + secrets.token_hex(4)}
        r_base = http.post(url, context, json=baseline_body, timeout=8)
        if r_base is None or r_base.status_code in (404, 405, 415):
            return []
        baseline_status = r_base.status_code
        baseline_len = len(r_base.text)

        findings: List[Finding] = []
        for key in baseline_body.keys():
            for payload in self.OPERATOR_PAYLOADS:
                test_body = dict(baseline_body)
                test_body[key] = payload
                response, req_ev, resp_ev = http.post(url, context, json=test_body, capture=True, timeout=8)
                if response is None:
                    continue
                status_improved = (
                    baseline_status >= 400 and response.status_code < 400
                    and response.status_code != baseline_status
                )
                body_grew = len(response.text) > baseline_len * self.BODY_GROWTH_THRESHOLD
                if status_improved or body_grew:
                    findings.append(Finding(
                        type="nosqli", severity="critical",
                        title=f"NoSQL Injection — clé '{key}'",
                        description=(
                            f"L'API {url} change de comportement quand la clé '{key}' reçoit un "
                            f"opérateur MongoDB ({json.dumps(payload)}) : statut {baseline_status}→"
                            f"{response.status_code}, taille {baseline_len}→{len(response.text)}."
                        ),
                        recommendation=(
                            "Typer et valider strictement les champs attendus (rejeter tout objet/opérateur "
                            "là où un scalaire est attendu). Utiliser une bibliothèque de validation de schéma."
                        ),
                        url=url, parameter=f"JSON body.{key}",
                        payload=json.dumps(test_body, ensure_ascii=False)[:200],
                        evidence=f"status {baseline_status}->{response.status_code}, taille {baseline_len}->{len(response.text)}",
                        confidence=80, cwe_id="CWE-943", owasp_id="A03:2021",
                        cvss_base=9.1,
                        detection_method="nosqli-behavioral-diff",
                        source="module:nosqli",
                        evidence_request=req_ev, evidence_response=resp_ev,
                    ))
                    break
        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && pytest tests/test_nosqli.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Add the taxonomy entry**

In `extension/src/utils/taxonomy.js`:
```javascript
"nosqli": {
  title: "NoSQL Injection",
  owasp: { id: "A03:2021", name: "Injection", url: "https://owasp.org/Top10/A03_2021-Injection/" },
  cwe:   { id: "CWE-943", name: "Improper Neutralization of Special Elements in Data Query Logic",
           url: "https://cwe.mitre.org/data/definitions/943.html" },
  cvssBase: 9.1,
  impact: "Contournement d'authentification ou fuite de données via opérateurs de requête (ex: MongoDB $gt/$ne).",
  references: [
    { label: "OWASP Testing for NoSQL Injection", url: "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection" },
  ],
},
```

- [ ] **Step 6: Commit**

```bash
git add backend/scanner/modules/nosqli.py backend/tests/test_nosqli.py extension/src/utils/taxonomy.js
git commit -m "feat(scanner): add dedicated NoSQL injection module for JSON API endpoints

json-fuzzer sent a {\"\$gt\": \"\"} payload but only ever confirmed it via
generic SQL error-message regexes, never via the actual NoSQLi signal
(auth bypass / extra data vs baseline).

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
```

---

## Final verification (whole Round 6)

- [ ] Run the complete backend suite: `cd backend && pytest tests/ -v` — expect all tests green, including the pre-existing `test_engine.py`, `test_crawler.py`, `test_oob.py`, `test_waf_detection.py`, `test_chain_rules.py`, `test_inference.py` files, which this round does not touch but must not have broken.
- [ ] Grep-verify no active module still imports raw `requests` for its own HTTP calls to the scanned target: `grep -rLn "scanner.core import http\|scanner.core.http" backend/scanner/modules/*.py` should list only files with no direct network call to the target (if any) — cross-check against the Global Constraints' explicit crawler/`crt.sh` exception.
- [ ] Confirm `GET /scanner/modules` (manually, via `curl http://127.0.0.1:9876/scanner/modules` with `backend/start.bat` running) now lists `ssti` and `nosqli` alongside the existing 24.
