"""
Command-line interface entry point.

This module wires together:
- configuration
- manifest loading
- rule evaluation
- filesystem scanning
- content transformation

It contains no business logic of its own.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from .config import load_encryption_key
from .manifest import Manifest
from .rules import RuleEngine
from .file_scanner import FileScanner
from .tranformer import Transformer, TransformMetadata


MANIFEST_PATH = ".encrypted_manifest.yml"


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def cmd_hide(args: argparse.Namespace) -> None:
    key = load_encryption_key()
    manifest = Manifest.load(args.manifest)
    profile = manifest.get_profile(args.profile)

    engine = RuleEngine(profile.rules)
    scanner = FileScanner(args.root, engine)
    transformer = Transformer(key)

    for path, decision in scanner.scan_text_files():
        transformer.hide(path, decision)


def cmd_reveal(args: argparse.Namespace) -> None:
    # Placeholder: metadata persistence/loading intentionally deferred
    raise RuntimeError("Reveal requires stored metadata (not implemented yet)")


def cmd_status(args: argparse.Namespace) -> None:
    manifest = Manifest.load(args.manifest)
    profile = manifest.get_profile(args.profile)

    engine = RuleEngine(profile.rules)
    scanner = FileScanner(args.root, engine)

    count = sum(1 for _ in scanner.scan())
    print(f"{count} files match encryption rules")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="encryptor")
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--root", default=".", help="Repository root")
    common.add_argument("--manifest", default=MANIFEST_PATH)
    common.add_argument("--profile", help="Manifest profile")

    p_hide = sub.add_parser("hide", parents=[common])
    p_hide.set_defaults(func=cmd_hide)

    p_reveal = sub.add_parser("reveal", parents=[common])
    p_reveal.set_defaults(func=cmd_reveal)

    p_status = sub.add_parser("status", parents=[common])
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
