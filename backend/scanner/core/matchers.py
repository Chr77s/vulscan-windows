"""
Moteur de matchers déclaratifs.

Un matcher décrit une condition sur une réponse HTTP : mot-clé (corps ou
en-têtes), regex, code de statut ou délai de réponse. Les payloads du
catalogue déclarent leurs matchers en JSON ; `evaluate` les combine en
`and` ou `or`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class HttpResult:
    status: int
    headers: dict
    body: str
    elapsed_ms: float = 0.0


@dataclass
class Matcher:
    type: str
    part: str = "body"
    words: List[str] = field(default_factory=list)
    regex: Optional[str] = None
    status_codes: List[int] = field(default_factory=list)
    min_delay_ms: Optional[float] = None
    negative: bool = False


def _matches(matcher: Matcher, result: HttpResult) -> bool:
    if matcher.type == "word":
        if matcher.part == "header":
            haystack = "\n".join(f"{k}: {v}" for k, v in result.headers.items())
        else:
            haystack = result.body
        haystack = haystack.lower()
        return any(word.lower() in haystack for word in matcher.words)
    if matcher.type == "regex":
        return re.search(matcher.regex, result.body, re.I) is not None
    if matcher.type == "status":
        return result.status in matcher.status_codes
    if matcher.type == "time":
        return matcher.min_delay_ms is not None and result.elapsed_ms >= matcher.min_delay_ms
    raise ValueError(f"Type de matcher inconnu : {matcher.type!r}")


def evaluate_matcher(matcher: Matcher, result: HttpResult) -> bool:
    matched = _matches(matcher, result)
    return not matched if matcher.negative else matched


def evaluate(matchers: List[Matcher], condition: str, result: HttpResult) -> bool:
    if not matchers:
        return False
    if condition == "and":
        return all(evaluate_matcher(m, result) for m in matchers)
    if condition == "or":
        return any(evaluate_matcher(m, result) for m in matchers)
    raise ValueError(f"Condition inconnue : {condition!r}")


def matchers_from_dicts(raw: List[dict]) -> List[Matcher]:
    return [Matcher(**d) for d in raw]
