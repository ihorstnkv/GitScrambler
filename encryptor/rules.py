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
from pathlib import Path, PurePath
from typing import List, Optional

from .manifest import RuleConfig
from .config import DEFAULT_CHUNK_SIZE


def matches_pattern(path: Path, pattern: str) -> bool:
    """
    Check if a path matches a glob pattern.

    Supports ** for recursive matching.
    """
    # Convert to PurePath for consistent matching
    pure_path = PurePath(path)

    # Try matching with pathlib's match (works from right-to-left)
    if pure_path.match(pattern):
        return True

    # For patterns with leading directories, also try full string match
    # This handles cases like "src/**/*.py" properly
    path_str = str(pure_path)
    pattern_parts = pattern.split('/')
    path_parts = path_str.split('/')

    # Simple recursive matching
    if '**' in pattern_parts:
        idx = pattern_parts.index('**')
        # Match prefix
        if idx > 0:
            prefix = '/'.join(pattern_parts[:idx])
            if not path_str.startswith(prefix):
                return False
        # Match suffix
        if idx < len(pattern_parts) - 1:
            suffix_pattern = '/'.join(pattern_parts[idx+1:])
            return pure_path.match(suffix_pattern)
        return True

    # Direct string comparison for simple patterns
    import fnmatch
    return fnmatch.fnmatch(path_str, pattern)


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

        for idx, rule in enumerate(self.rules):
            # Check if path matches include pattern
            if not matches_pattern(path, rule.include):
                continue

            # Check exclusions
            if any(matches_pattern(path, pat) for pat in rule.exclude):
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