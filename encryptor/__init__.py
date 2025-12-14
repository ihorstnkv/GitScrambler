"""
Encrypted Repo Scrambler

A pre-commit enforcement tool that scrambles and encrypts selected
repository content to prevent accidental or casual disclosure in
public Git repositories.
"""

__version__ = "0.1.0"

from .config import load_encryption_key, DEFAULT_PROFILE
from .manifest import Manifest
from .rules import RuleEngine, RuleDecision
from .tranformer import Transformer, hide_file, reveal_file

__all__ = [
    "load_encryption_key",
    "DEFAULT_PROFILE",
    "Manifest",
    "RuleEngine",
    "RuleDecision",
    "Transformer",
    "hide_file",
    "reveal_file",
]