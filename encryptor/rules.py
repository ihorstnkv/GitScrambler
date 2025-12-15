"""
Rule evaluation logic.

Given a file path and a set of rules, this module decides:
- whether the file is affected
- which rule applies
- what actions should be taken

Rules DO NOT perform actions. They only return decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import fnmatch

from .manifest import RuleConfig
from .config import DEFAULT_CHUNK_SIZE


@dataclass(frozen=True)
class RuleDecision:
    matched: bool
    encrypt: bool
    scramble: bool
    chunk_size: int
    rule_index: Optional[int] = None


class RuleEngine:
    def __init__(self, rules: List[RuleConfig]):
        self.rules = rules

    def evaluate(self, path: str | Path) -> RuleDecision:
        path = Path(path)
        path_str = path.as_posix()

        for idx, rule in enumerate(self.rules):
            if not fnmatch.fnmatch(path_str, rule.include):
                continue

            if any(fnmatch.fnmatch(path_str, pat) for pat in rule.exclude):
                continue

            return RuleDecision(
                matched=True,
                encrypt=bool(rule.encrypt if rule.encrypt is not None else True),
                scramble=bool(rule.scramble if rule.scramble is not None else True),
                chunk_size=rule.chunk_size or DEFAULT_CHUNK_SIZE,
                rule_index=idx,
            )

        return RuleDecision(
            matched=False,
            encrypt=False,
            scramble=False,
            chunk_size=DEFAULT_CHUNK_SIZE,
            rule_index=None,
        )
