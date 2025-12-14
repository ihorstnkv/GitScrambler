"""
Filesystem scanning and rule application.

This module is responsible for:
- walking the repository tree
- applying rule decisions to files
- yielding files that should be transformed

This module does NOT:
- encrypt or scramble data
- modify files
- load configuration or manifest files
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator, Tuple

from .rules import RuleEngine, RuleDecision
from .utils import is_binary_file


class FileScanner:
    def __init__(self, root: str | Path, rule_engine: RuleEngine):
        self.root = Path(root)
        self.rule_engine = rule_engine

    def scan(self) -> Iterator[Tuple[Path, RuleDecision]]:
        """
        Walk the filesystem and yield files that match at least one rule.

        Yields:
            (Path, RuleDecision)
        """

        for path in self.root.rglob("*"):
            if not path.is_file():
                continue

            # Convert to relative path for rule evaluation
            try:
                rel_path = path.relative_to(self.root)
            except ValueError:
                # Path is not relative to root, skip it
                continue

            decision = self.rule_engine.evaluate(rel_path)
            if not decision.matched:
                continue

            # Yield absolute path but evaluated against relative
            yield path, decision

    def scan_text_files(self) -> Iterator[Tuple[Path, RuleDecision]]:
        """
        Yield only non-binary files that match rules.
        """

        for path, decision in self.scan():
            if is_binary_file(path):
                continue

            yield path, decision