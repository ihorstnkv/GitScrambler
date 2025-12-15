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
from .transformer import Transformer, TransformMetadata


MANIFEST_PATH = ".manifest.yml"


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

    files_processed = 0
    for path, decision in scanner.scan_text_files():
        if args.verbose:
            rel_path = path.relative_to(args.root) if path.is_absolute() else path
            print(f"Encrypting: {rel_path}")

        transformer.hide(path, decision)
        files_processed += 1

    if files_processed == 0:
        print("No files to encrypt")
    else:
        print(f"\n✓ Successfully encrypted {files_processed} file{'s' if files_processed != 1 else ''}")


def cmd_reveal(args: argparse.Namespace) -> None:
    # Placeholder: metadata persistence/loading intentionally deferred
    raise RuntimeError("Reveal requires stored metadata (not implemented yet)")


def cmd_status(args: argparse.Namespace) -> None:
    manifest = Manifest.load(args.manifest)
    profile = manifest.get_profile(args.profile)

    engine = RuleEngine(profile.rules)
    scanner = FileScanner(args.root, engine)

    files = list(scanner.scan())
    count = len(files)

    if count == 0:
        print("No files match encryption rules")
        return

    print(f"Found {count} file{'s' if count != 1 else ''} matching encryption rules:")

    if args.verbose:
        print()
        for path, decision in files:
            rel_path = path.relative_to(args.root) if path.is_absolute() else path
            actions = []
            if decision.encrypt:
                actions.append("encrypt")
            if decision.scramble:
                actions.append(f"scramble (chunk_size={decision.chunk_size})")
            action_str = ", ".join(actions) if actions else "none"
            print(f"  • {rel_path}")
            print(f"    Actions: {action_str}")
    else:
        print("Use --verbose to see the full file list and details")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="encryptor",
        description="""
Encryptor - Pre-commit encryption tool for Git repositories

Scramble and encrypt sensitive files before committing to version control.
This tool helps you store proprietary code in public/shared repositories
by encrypting files according to rules defined in .manifest.yml
        """.strip(),
        epilog="""
TYPICAL WORKFLOW:
  1. Create .manifest.yml with encryption rules
  2. Set ENCRYPTION_KEY environment variable
  3. Run 'encryptor status' to preview affected files
  4. Run 'encryptor hide' before committing
  5. Run 'encryptor reveal' after pulling to work on files

EXAMPLES:
  # Check which files will be encrypted
  $ encryptor status

  # Preview with custom manifest
  $ encryptor status --manifest config/secure.yml

  # Encrypt all matching files (requires ENCRYPTION_KEY)
  $ export ENCRYPTION_KEY="your-secret-key-here"
  $ encryptor hide

  # Encrypt using a specific profile
  $ encryptor hide --profile production

  # Decrypt files back to original state
  $ encryptor reveal

  # Work on a different repository
  $ encryptor hide --root /path/to/repo

ENVIRONMENT VARIABLES:
  ENCRYPTION_KEY      Encryption key (required for hide/reveal)
  ENCRYPTOR_MODE      Execution mode: 'dev' or 'prod' (default: prod)

MANIFEST FILE (.manifest.yml):
  The manifest defines which files to encrypt and how. It must contain:
  - version: manifest format version (currently 1)
  - profiles: named sets of encryption rules
  - rules: include/exclude patterns using glob syntax

  See documentation for manifest file format and examples.

NOTES:
  - Files are encrypted in-place and overwrite the original
  - Always commit encrypted files, never plaintext
  - Keep your ENCRYPTION_KEY secret and never commit it
  - All team members need the same ENCRYPTION_KEY to decrypt
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(
        dest="command",
        required=True,
        title="commands",
        description="Available commands",
    )

    # Common arguments shared across all commands
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--root",
        default=".",
        metavar="PATH",
        help="repository root directory (default: current directory)",
    )
    common.add_argument(
        "--manifest",
        default=MANIFEST_PATH,
        metavar="FILE",
        help=f"manifest file path (default: {MANIFEST_PATH})",
    )
    common.add_argument(
        "--profile",
        metavar="NAME",
        help="manifest profile name (default: 'default')",
    )
    common.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="enable verbose output with detailed information",
    )

    # Hide command
    p_hide = sub.add_parser(
        "hide",
        parents=[common],
        help="encrypt and scramble files according to manifest rules",
        description="""
Encrypt and scramble repository files matching the manifest rules.

WHEN TO USE:
  Run this command BEFORE committing sensitive code to version control.
  After running, the specified files will be encrypted in-place.

REQUIREMENTS:
  - ENCRYPTION_KEY environment variable must be set
  - .manifest.yml file must exist (or specify with --manifest)
  - Files must be readable and writable

BEHAVIOR:
  - Encrypts files using AES-GCM encryption
  - Optionally scrambles content by chunk for obfuscation
  - Overwrites original files with encrypted versions
  - Metadata is stored for later decryption (future feature)

WARNING:
  This operation modifies files in-place. Commit encrypted files only.
  Make sure you have backups or use version control properly.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_hide.set_defaults(func=cmd_hide)

    # Reveal command
    p_reveal = sub.add_parser(
        "reveal",
        parents=[common],
        help="decrypt and restore files to original state",
        description="""
Decrypt and unscramble files back to their original, readable state.

WHEN TO USE:
  Run this command AFTER pulling encrypted changes or when you need to
  work on the code. This reverses the 'hide' operation.

REQUIREMENTS:
  - ENCRYPTION_KEY environment variable (same key used for 'hide')
  - Metadata from previous 'hide' operation (stored in .encryptor/)
  - Files must be readable and writable

BEHAVIOR:
  - Decrypts using AES-GCM with original nonce and tag
  - Unscrambles chunks back to original order
  - Overwrites encrypted files with plaintext versions

NOTE:
  Current implementation requires metadata persistence feature (WIP).
  This command will be fully functional in a future release.

WARNING:
  Never commit decrypted (revealed) files. Always run 'hide' before commit.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_reveal.set_defaults(func=cmd_reveal)

    # Status command
    p_status = sub.add_parser(
        "status",
        parents=[common],
        help="preview which files will be affected by encryption rules",
        description="""
Display all files that match your manifest's encryption rules.

WHEN TO USE:
  Use this command to preview and verify your manifest configuration
  BEFORE running 'hide'. This helps you catch mistakes in your rules.

REQUIREMENTS:
  - .manifest.yml file must exist (or specify with --manifest)
  - No encryption key needed

BEHAVIOR:
  - Scans repository according to manifest rules
  - Shows count of matching files
  - Does NOT modify any files
  - Does NOT require ENCRYPTION_KEY

OUTPUT:
  Displays the total number of files that would be encrypted
  if you ran 'encryptor hide' with the same options.

EXAMPLES:
  # Check default manifest
  $ encryptor status

  # Check specific profile
  $ encryptor status --profile production

  # Check custom manifest location
  $ encryptor status --manifest config/my-rules.yml
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_status.set_defaults(func=cmd_status)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()