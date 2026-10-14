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
