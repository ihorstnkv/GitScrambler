"""
Command-line interface for the encryptor tool.

This module orchestrates all other components and provides
the user-facing CLI commands:
- hide
- reveal
- status
- explain
- rules
- help
"""

from __future__ import annotations

import sys
import argparse
from pathlib import Path
from typing import List, Optional, NoReturn

from .config import (
    load_encryption_key,
    DEFAULT_PROFILE,
    TOOL_VERSION,
)
from .manifest import Manifest
from .rules import RuleEngine
from .file_scanner import FileScanner
from .transformer import Transformer


# ---------------------------------------------------------------------------
# Color output helpers
# ---------------------------------------------------------------------------


class Colors:
    """ANSI color codes for terminal output."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"


def colored(text: str, color: str) -> str:
    """Return colored text for terminal output."""
    return f"{color}{text}{Colors.RESET}"


def print_error(msg: str) -> None:
    """Print error message to stderr."""
    print(colored(f"✗ Error: {msg}", Colors.RED), file=sys.stderr)


def print_success(msg: str) -> None:
    """Print success message."""
    print(colored(f"✓ {msg}", Colors.GREEN))


def print_warning(msg: str) -> None:
    """Print warning message."""
    print(colored(f"⚠ Warning: {msg}", Colors.YELLOW))


def print_info(msg: str) -> None:
    """Print info message."""
    print(colored(f"ℹ {msg}", Colors.CYAN))


# ---------------------------------------------------------------------------
# CLI context
# ---------------------------------------------------------------------------


class CLIContext:
    """Shared context for CLI commands."""

    def __init__(
        self,
        manifest_path: str,
        profile: str,
        verbose: bool,
        quiet: bool,
        dry_run: bool,
    ):
        self.manifest_path = Path(manifest_path)
        self.profile = profile
        self.verbose = verbose
        self.quiet = quiet
        self.dry_run = dry_run

        # Lazy-loaded
        self._manifest: Optional[Manifest] = None
        self._key: Optional[bytes] = None
        self._transformer: Optional[Transformer] = None

    @property
    def manifest(self) -> Manifest:
        """Load manifest lazily."""
        if self._manifest is None:
            try:
                self._manifest = Manifest.load(self.manifest_path)
            except Exception as e:
                print_error(f"Failed to load manifest: {e}")
                sys.exit(1)
        return self._manifest

    @property
    def key(self) -> bytes:
        """Load encryption key lazily."""
        if self._key is None:
            try:
                self._key = load_encryption_key()
            except RuntimeError as e:
                print_error(str(e))
                sys.exit(1)
        return self._key

    @property
    def transformer(self) -> Transformer:
        """Create transformer lazily."""
        if self._transformer is None:
            self._transformer = Transformer(self.key)
        return self._transformer

    def log(self, msg: str) -> None:
        """Log message if not quiet."""
        if not self.quiet:
            print(msg)

    def log_verbose(self, msg: str) -> None:
        """Log message if verbose."""
        if self.verbose:
            print(colored(f"  → {msg}", Colors.BLUE))


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_hide(ctx: CLIContext, args: argparse.Namespace) -> int:
    """
    Scramble and encrypt files according to the manifest.
    """
    manifest = ctx.manifest
    profile = manifest.get_profile(ctx.profile)

    ctx.log(colored(f"Hiding files (profile: {ctx.profile})", Colors.BOLD))

    # Build rule engine
    rule_engine = RuleEngine(profile.rules)

    # Determine root directory
    root = Path.cwd()

    # Scan files
    scanner = FileScanner(root, rule_engine)

    if args.staged_only:
        ctx.log_verbose("Processing only Git-staged files")
        # TODO: integrate with git to get staged files
        print_warning("--staged-only not yet implemented")

    # Debug: show what we're scanning
    ctx.log_verbose(f"Scanning directory: {root}")

    files_to_process = []
    total_scanned = 0
    total_matched = 0

    for file_path, decision in scanner.scan():
        total_scanned += 1
        ctx.log_verbose(f"Found file: {file_path} (matched={decision.matched})")

        if not decision.matched:
            continue

        total_matched += 1

        # Skip if neither scramble nor encrypt
        if not decision.scramble and not decision.encrypt:
            ctx.log_verbose(f"Skipping {file_path} (no actions)")
            continue

        files_to_process.append((file_path, decision))

    ctx.log_verbose(f"Scanned {total_scanned} files, {total_matched} matched rules")

    if not files_to_process:
        ctx.log(colored("No files to process", Colors.YELLOW))
        if ctx.verbose:
            ctx.log(f"Hint: Run 'encryptor -m manifest.yml rules -v' to see file counts")
        return 0

    if ctx.dry_run:
        ctx.log(colored(f"\n[DRY RUN] Preview of changes:", Colors.YELLOW))

    ctx.log(f"Found {len(files_to_process)} file(s) to process")

    # Process files
    processed_count = 0
    failed_count = 0

    for file_path, decision in files_to_process:
        ctx.log_verbose(f"Processing: {file_path}")

        output_path = file_path.with_suffix(file_path.suffix + ".enc")

        if ctx.dry_run:
            # Show detailed preview in dry-run mode
            actions = []
            if decision.scramble:
                actions.append(f"scramble (chunk_size={decision.chunk_size})")
            if decision.encrypt:
                actions.append("encrypt (AES-GCM)")

            action_str = " + ".join(actions) if actions else "no action"
            ctx.log(f"  {colored('→', Colors.CYAN)} {file_path}")
            ctx.log(f"    Actions: {action_str}")
            ctx.log(f"    Output:  {output_path}")
            ctx.log(f"    Rule:    #{decision.rule_index}")
            processed_count += 1
            continue

        try:
            # Override settings if flags provided
            scramble = not args.no_scramble if hasattr(args, 'no_scramble') else decision.scramble
            encrypt = not args.no_encrypt if hasattr(args, 'no_encrypt') else decision.encrypt
            chunk_size = args.chunk_size if hasattr(args, 'chunk_size') and args.chunk_size else decision.chunk_size
            deterministic = args.deterministic if hasattr(args, 'deterministic') else False

            transformer = Transformer(ctx.key, deterministic=deterministic)
            transformer.hide_file(
                file_path,
                output_path,
                scramble=scramble,
                encrypt=encrypt,
                chunk_size=chunk_size,
            )

            # Remove original if configured
            if not ctx.dry_run:
                file_path.unlink()

            ctx.log(f"  ✓ {file_path} → {output_path}")
            processed_count += 1

        except Exception as e:
            print_error(f"Failed to process {file_path}: {e}")
            failed_count += 1
            if not args.force:
                return 1

    # Summary
    ctx.log("")
    if ctx.dry_run:
        ctx.log(colored(f"[DRY RUN] Preview complete - no files were modified", Colors.YELLOW))
        ctx.log(f"Would process {processed_count} file(s)")
        return 0

    if failed_count > 0:
        print_warning(f"Processed {processed_count} file(s), {failed_count} failed")
        return 1
    else:
        print_success(f"Successfully processed {processed_count} file(s)")
        return 0


def cmd_reveal(ctx: CLIContext, args: argparse.Namespace) -> int:
    """
    Restore original content by decrypting and unscrambling files.
    """
    ctx.log(colored("⚠️  WARNING: This will restore plaintext content", Colors.YELLOW))
    ctx.log(colored("   Do NOT commit revealed files", Colors.YELLOW))

    # If specific paths provided, only reveal those
    target_paths: List[Path] = []
    if args.paths:
        target_paths = [Path(p) for p in args.paths]
    else:
        # Reveal all .enc files in the repository
        root = Path.cwd()
        target_paths = list(root.rglob("*.enc"))

    if not target_paths:
        ctx.log(colored("No encrypted files found", Colors.YELLOW))
        return 0

    if ctx.dry_run:
        ctx.log(colored(f"\n[DRY RUN] Preview of changes:", Colors.YELLOW))

    ctx.log(f"Found {len(target_paths)} encrypted file(s)")

    # Confirmation prompt
    if not args.force and not ctx.dry_run:
        ctx.log("")
        response = input(colored("Continue? [y/N] ", Colors.YELLOW))
        if response.lower() not in ["y", "yes"]:
            ctx.log("Aborted")
            return 0

    # Process files
    processed_count = 0
    failed_count = 0

    for enc_path in target_paths:
        if not enc_path.suffix == ".enc":
            ctx.log_verbose(f"Skipping non-encrypted file: {enc_path}")
            continue

        # Determine output path (remove .enc suffix)
        output_path = enc_path.with_suffix("")

        ctx.log_verbose(f"Revealing: {enc_path}")

        if ctx.dry_run:
            try:
                # Read metadata in dry-run to show details
                metadata = ctx.transformer.read_metadata(enc_path.read_bytes())
                ctx.log(f"  {colored('→', Colors.CYAN)} {enc_path}")
                ctx.log(f"    Output:       {output_path}")
                ctx.log(f"    Original size: {metadata.original_size} bytes")
                ctx.log(f"    Chunks:       {len(metadata.permutation)}")
                ctx.log(f"    Scrambled:    {'yes' if len(metadata.permutation) > 1 else 'no'}")
            except Exception as e:
                ctx.log(f"  {colored('✗', Colors.RED)} {enc_path}")
                ctx.log(f"    Error: {str(e)}")
            processed_count += 1
            continue

        try:
            if args.headers_only:
                # Only decrypt and show metadata
                metadata = ctx.transformer.read_metadata(enc_path.read_bytes())
                ctx.log(f"\n{colored('Metadata for:', Colors.BOLD)} {enc_path}")
                ctx.log(f"  {colored('File Information:', Colors.CYAN)}")
                ctx.log(f"    Original filename: {metadata.original_filename or 'unknown'}")
                ctx.log(f"    Original size:     {metadata.original_size} bytes")
                ctx.log(f"    Version:           {metadata.version}")
                ctx.log(f"\n  {colored('Transformation:', Colors.CYAN)}")
                ctx.log(f"    Scrambled:         {colored('yes' if metadata.scrambled else 'no', Colors.GREEN if metadata.scrambled else Colors.YELLOW)}")
                ctx.log(f"    Encrypted:         {colored('yes' if metadata.encrypted else 'no', Colors.GREEN if metadata.encrypted else Colors.YELLOW)}")
                ctx.log(f"\n  {colored('Scrambling Details:', Colors.CYAN)}")
                ctx.log(f"    Chunk size:        {metadata.chunk_size} bytes")
                ctx.log(f"    Total chunks:      {len(metadata.permutation)}")
                ctx.log(f"    Chunk lengths:     {metadata.chunk_lengths}")
                if metadata.scrambled and len(metadata.permutation) > 1:
                    # Check if chunks were actually permuted
                    is_identity = metadata.permutation == list(range(len(metadata.permutation)))
                    ctx.log(f"    Permutation:       {'identity (no shuffle)' if is_identity else 'shuffled'}")
            else:
                # Full restore
                ctx.transformer.reveal_file(enc_path, output_path)

                # Remove encrypted file
                if not ctx.dry_run and not args.no_filenames:
                    enc_path.unlink()

                ctx.log(f"  ✓ {enc_path} → {output_path}")

            processed_count += 1

        except Exception as e:
            print_error(f"Failed to reveal {enc_path}: {e}")
            failed_count += 1
            if not args.partial:
                return 1

    # Summary
    ctx.log("")
    if ctx.dry_run:
        ctx.log(colored(f"[DRY RUN] Preview complete - no files were modified", Colors.YELLOW))
        ctx.log(f"Would reveal {processed_count} file(s)")
        return 0

    if failed_count > 0:
        print_warning(f"Revealed {processed_count} file(s), {failed_count} failed")
        return 1
    else:
        print_success(f"Successfully revealed {processed_count} file(s)")
        return 0


def cmd_status(ctx: CLIContext, args: argparse.Namespace) -> int:
    """
    Show repository encryption status.
    """
    manifest = ctx.manifest
    profile = manifest.get_profile(ctx.profile)

    root = Path.cwd()

    # Count encrypted files
    encrypted_files = list(root.rglob("*.enc"))

    # Build rule engine
    rule_engine = RuleEngine(profile.rules)
    scanner = FileScanner(root, rule_engine)

    # Count files that should be encrypted but aren't
    plaintext_violations = []
    for file_path, decision in scanner.scan():
        if decision.matched and decision.encrypt:
            # Check if .enc version exists
            enc_path = file_path.with_suffix(file_path.suffix + ".enc")
            if not enc_path.exists():
                plaintext_violations.append(file_path)

    if args.json:
        import json
        output = {
            "encrypted_files": len(encrypted_files),
            "plaintext_violations": len(plaintext_violations),
            "active_profile": ctx.profile,
            "manifest_version": manifest.version,
        }
        print(json.dumps(output, indent=2))
        return 0

    # Human-readable output
    ctx.log(colored("Repository Status", Colors.BOLD))
    ctx.log("")
    ctx.log(f"  Manifest version:     {manifest.version}")
    ctx.log(f"  Active profile:       {ctx.profile}")
    ctx.log(f"  Encrypted files:      {len(encrypted_files)}")
    ctx.log(f"  Plaintext violations: {len(plaintext_violations)}")

    if plaintext_violations:
        ctx.log("")
        print_warning("Plaintext violations detected:")
        for path in plaintext_violations[:10]:  # Show first 10
            ctx.log(f"    - {path}")
        if len(plaintext_violations) > 10:
            ctx.log(f"    ... and {len(plaintext_violations) - 10} more")

    ctx.log("")

    # Exit with error if violations in CI mode
    if args.ci and plaintext_violations:
        return 1

    return 0


def cmd_explain(ctx: CLIContext, args: argparse.Namespace) -> int:
    """
    Explain why a file is affected by the manifest.
    """
    if not args.path:
        print_error("No path provided")
        return 1

    manifest = ctx.manifest
    profile = manifest.get_profile(ctx.profile)
    rule_engine = RuleEngine(profile.rules)

    file_path = Path(args.path)

    # Check if file exists
    file_exists = file_path.exists()
    is_encrypted = file_path.suffix == ".enc"

    ctx.log(colored(f"\n{'='*60}", Colors.CYAN))
    ctx.log(colored(f"Rule Evaluation", Colors.BOLD))
    ctx.log(colored(f"{'='*60}\n", Colors.CYAN))

    ctx.log(f"{colored('File:', Colors.BOLD)} {file_path}")
    ctx.log(f"{colored('Exists:', Colors.BOLD)} {colored('Yes', Colors.GREEN) if file_exists else colored('No', Colors.RED)}")
    if is_encrypted:
        ctx.log(f"{colored('Type:', Colors.BOLD)} {colored('Encrypted (.enc)', Colors.YELLOW)}")
    ctx.log(f"{colored('Profile:', Colors.BOLD)} {ctx.profile}\n")

    # Evaluate against rules
    decision = rule_engine.evaluate(file_path)

    if not decision.matched:
        ctx.log(colored("Result:", Colors.BOLD))
        ctx.log(colored("  ✗ NOT MATCHED by any rule", Colors.RED))
        ctx.log("\nThis file will be IGNORED by encryptor.\n")

        # Show why it didn't match
        if ctx.verbose:
            ctx.log(colored("Rule Analysis:", Colors.CYAN))
            for idx, rule in enumerate(profile.rules):
                ctx.log(f"\n  Rule #{idx}:")
                ctx.log(f"    Include: {rule.include}")
                if rule.exclude:
                    ctx.log(f"    Exclude: {', '.join(rule.exclude)}")

                # Check include pattern
                from .rules import matches_pattern
                include_match = matches_pattern(file_path, rule.include)
                ctx.log(f"    Include match: {colored('✓', Colors.GREEN) if include_match else colored('✗', Colors.RED)}")

                # Check exclude patterns
                if include_match and rule.exclude:
                    for exclude_pat in rule.exclude:
                        exclude_match = matches_pattern(file_path, exclude_pat)
                        if exclude_match:
                            ctx.log(f"    Excluded by: {exclude_pat} {colored('✓', Colors.YELLOW)}")

        ctx.log(colored(f"{'='*60}\n", Colors.CYAN))
        return 0

    # File matched
    ctx.log(colored("Result:", Colors.BOLD))
    ctx.log(colored("  ✓ MATCHED", Colors.GREEN))

    ctx.log(f"\n{colored('Matched Rule:', Colors.CYAN)}")
    ctx.log(f"  Index:      #{decision.rule_index}")

    if decision.rule_index is not None:
        rule = profile.rules[decision.rule_index]
        ctx.log(f"  Include:    {rule.include}")
        if rule.exclude:
            ctx.log(f"  Exclude:    {', '.join(rule.exclude)}")

    ctx.log(f"\n{colored('Actions to Apply:', Colors.CYAN)}")
    ctx.log(f"  Scramble:   {colored('✓ YES', Colors.GREEN) if decision.scramble else colored('✗ NO', Colors.YELLOW)}")
    ctx.log(f"  Encrypt:    {colored('✓ YES', Colors.GREEN) if decision.encrypt else colored('✗ NO', Colors.YELLOW)}")
    ctx.log(f"  Chunk size: {decision.chunk_size} bytes")

    # Show what will happen
    ctx.log(f"\n{colored('Effect:', Colors.CYAN)}")
    if decision.encrypt:
        output_path = file_path.with_suffix(file_path.suffix + ".enc")
        ctx.log(f"  When 'hide' runs:")
        ctx.log(f"    Input:  {file_path}")
        ctx.log(f"    Output: {output_path}")
        ctx.log(f"    Original file will be REMOVED")
    else:
        ctx.log(f"  File will be PROCESSED but not encrypted")

    ctx.log(colored(f"\n{'='*60}\n", Colors.CYAN))
    return 0


def cmd_rules(ctx: CLIContext, args: argparse.Namespace) -> int:
    """
    Inspect and debug rule evaluation.
    """
    manifest = ctx.manifest
    profile = manifest.get_profile(ctx.profile)

    ctx.log(colored(f"Rules for profile: {ctx.profile}", Colors.BOLD))
    ctx.log("")

    for idx, rule in enumerate(profile.rules):
        ctx.log(colored(f"Rule {idx}:", Colors.CYAN))
        ctx.log(f"  Include:    {rule.include}")
        if rule.exclude:
            ctx.log(f"  Exclude:    {', '.join(rule.exclude)}")
        ctx.log(f"  Scramble:   {rule.scramble if rule.scramble is not None else 'default (true)'}")
        ctx.log(f"  Encrypt:    {rule.encrypt if rule.encrypt is not None else 'default (true)'}")
        ctx.log(f"  Chunk size: {rule.chunk_size if rule.chunk_size else 'default'}")

        # Count matching files if verbose
        if args.verbose:
            rule_engine = RuleEngine([rule])
            scanner = FileScanner(Path.cwd(), rule_engine)
            matches = list(scanner.scan())
            ctx.log(f"  Matches:    {len(matches)} file(s)")

        ctx.log("")

    return 0


def cmd_inspect(ctx: CLIContext, args: argparse.Namespace) -> int:
    """
    Inspect an encrypted file and show detailed metadata.
    """
    if not args.path:
        print_error("No path provided")
        return 1

    file_path = Path(args.path)

    if not file_path.exists():
        print_error(f"File not found: {file_path}")
        return 1

    if not file_path.suffix == ".enc":
        print_warning(f"File does not have .enc extension: {file_path}")

    ctx.log(colored(f"\n{'='*60}", Colors.CYAN))
    ctx.log(colored(f"Encrypted File Inspection", Colors.BOLD))
    ctx.log(colored(f"{'='*60}\n", Colors.CYAN))

    try:
        # Read encrypted content
        encrypted_content = file_path.read_bytes()
        ctx.log(f"{colored('File:', Colors.BOLD)} {file_path}")
        ctx.log(f"{colored('Size:', Colors.BOLD)} {len(encrypted_content)} bytes\n")

        # Read and display metadata
        metadata = ctx.transformer.read_metadata(encrypted_content)

        ctx.log(colored('File Information:', Colors.CYAN))
        ctx.log(f"  Original filename:  {metadata.original_filename or 'unknown'}")
        ctx.log(f"  Original size:      {metadata.original_size} bytes")
        ctx.log(f"  Metadata version:   {metadata.version}")

        ctx.log(f"\n{colored('Transformation Applied:', Colors.CYAN)}")
        ctx.log(f"  Scrambled:          {colored('✓ YES' if metadata.scrambled else '✗ NO', Colors.GREEN if metadata.scrambled else Colors.YELLOW)}")
        ctx.log(f"  Encrypted:          {colored('✓ YES' if metadata.encrypted else '✗ NO', Colors.GREEN if metadata.encrypted else Colors.YELLOW)}")

        ctx.log(f"\n{colored('Scrambling Configuration:', Colors.CYAN)}")
        ctx.log(f"  Chunk size:         {metadata.chunk_size} bytes")
        ctx.log(f"  Total chunks:       {len(metadata.permutation)}")
        ctx.log(f"  Chunk lengths:      {metadata.chunk_lengths}")

        if metadata.scrambled and len(metadata.permutation) > 1:
            is_identity = metadata.permutation == list(range(len(metadata.permutation)))
            ctx.log(f"  Permutation type:   {'Identity (not shuffled)' if is_identity else 'Shuffled'}")
            if not is_identity and ctx.verbose:
                ctx.log(f"  Permutation map:    {metadata.permutation}")

        ctx.log(f"\n{colored('Encryption Details:', Colors.CYAN)}")
        ctx.log(f"  Algorithm:          AES-GCM")
        ctx.log(f"  Authenticated:      Yes")

        # Calculate size overhead
        overhead = len(encrypted_content) - metadata.original_size
        overhead_pct = (overhead / metadata.original_size * 100) if metadata.original_size > 0 else 0
        ctx.log(f"\n{colored('Storage Analysis:', Colors.CYAN)}")
        ctx.log(f"  Original:           {metadata.original_size} bytes")
        ctx.log(f"  Encrypted:          {len(encrypted_content)} bytes")
        ctx.log(f"  Overhead:           {overhead} bytes ({overhead_pct:.1f}%)")

        ctx.log(colored(f"\n{'='*60}\n", Colors.CYAN))

        return 0

    except Exception as e:
        print_error(f"Failed to inspect file: {e}")
        if ctx.verbose:
            import traceback
            traceback.print_exc()
        return 1


def cmd_help(ctx: CLIContext, args: argparse.Namespace) -> int:
    """
    Show help message.
    """
    help_text = f"""
{colored('encryptor', Colors.BOLD)} — scramble and encrypt repository content

{colored('USAGE:', Colors.CYAN)}
  encryptor <command> [options] [paths...]

{colored('DESCRIPTION:', Colors.CYAN)}
  encryptor is a pre-commit enforcement tool that scrambles and encrypts
  selected repository files to prevent accidental or casual disclosure
  in public Git repositories.

  Files are unreadable by default. Restoring content requires an explicit
  command and a secret key.

{colored('COMMANDS:', Colors.CYAN)}
  hide        Scramble and encrypt files according to the manifest
  reveal      Restore original content (explicit and manual)
  status      Show repository encryption status
  explain     Explain why a file is affected
  rules       Inspect and debug rule evaluation
  inspect     Show detailed metadata for an encrypted file
  help        Show this help message

{colored('GLOBAL OPTIONS:', Colors.CYAN)}
  -m, --manifest PATH       Path to manifest file
                            (default: manifest.yml)
  -p, --profile NAME        Rule profile to use
                            (default: default)
  -n, --dry-run             Show what would happen without modifying files
  -v, --verbose             Enable verbose output
  -q, --quiet               Suppress non-error output
  -h, --help                Show this help message and exit

{colored('ENVIRONMENT:', Colors.CYAN)}
  ENCRYPTION_KEY            Secret key used for encryption and scrambling
                            (required for hide and reveal)
  ENCRYPTOR_MODE            Optional execution mode (e.g. dev, prod)

{colored('EXAMPLES:', Colors.CYAN)}
  encryptor hide
  encryptor hide --dry-run
  encryptor reveal
  encryptor reveal src/private/auth.py
  encryptor explain src/private/auth.py
  encryptor status

{colored('VERSION:', Colors.CYAN)}
  {TOOL_VERSION}
"""
    print(help_text)
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="encryptor",
        description="Scramble and encrypt repository content",
        add_help=False,
    )

    # Global options
    parser.add_argument(
        "-m", "--manifest",
        default="manifest.yml",
        help="Path to manifest file",
    )
    parser.add_argument(
        "-p", "--profile",
        default=DEFAULT_PROFILE,
        help="Rule profile to use",
    )
    parser.add_argument(
        "-n", "--dry-run",
        action="store_true",
        help="Show what would happen without modifying files",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress non-error output",
    )
    parser.add_argument(
        "-h", "--help",
        action="store_true",
        help="Show help message",
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # hide command
    hide_parser = subparsers.add_parser("hide", help="Scramble and encrypt files")
    hide_parser.add_argument("--force", action="store_true", help="Proceed even if warnings are detected")
    hide_parser.add_argument("--deterministic", action="store_true", help="Enable deterministic scrambling")
    hide_parser.add_argument("--staged-only", action="store_true", help="Process only Git-staged files")
    hide_parser.add_argument("--fail-on-plaintext", action="store_true", help="Fail if plaintext detected")
    hide_parser.add_argument("--no-scramble", action="store_true", help="Disable scrambling")
    hide_parser.add_argument("--no-encrypt", action="store_true", help="Disable encryption")
    hide_parser.add_argument("--chunk-size", type=int, help="Override default scramble chunk size")

    # reveal command
    reveal_parser = subparsers.add_parser("reveal", help="Restore original content")
    reveal_parser.add_argument("paths", nargs="*", help="Specific files to reveal")
    reveal_parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    reveal_parser.add_argument("--headers-only", action="store_true", help="Decrypt and display metadata only")
    reveal_parser.add_argument("--no-filenames", action="store_true", help="Do not restore original filenames")
    reveal_parser.add_argument("--partial", action="store_true", help="Allow partial restore if some files fail")

    # status command
    status_parser = subparsers.add_parser("status", help="Show repository state")
    status_parser.add_argument("--ci", action="store_true", help="CI-safe output")
    status_parser.add_argument("--json", action="store_true", help="Output status as JSON")

    # explain command
    explain_parser = subparsers.add_parser("explain", help="Explain rule matching")
    explain_parser.add_argument("path", help="File path to explain")

    # rules command
    rules_parser = subparsers.add_parser("rules", help="Inspect rule evaluation")

    # inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Show detailed encrypted file metadata")
    inspect_parser.add_argument("path", help="Path to encrypted file")

    # help command
    subparsers.add_parser("help", help="Show help message")

    return parser


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    """Main CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Show help if requested or no command
    if args.help or not args.command:
        return cmd_help(None, args)

    # Build context
    ctx = CLIContext(
        manifest_path=args.manifest,
        profile=args.profile,
        verbose=args.verbose,
        quiet=args.quiet,
        dry_run=args.dry_run,
    )

    # Dispatch to command
    commands = {
        "hide": cmd_hide,
        "reveal": cmd_reveal,
        "status": cmd_status,
        "explain": cmd_explain,
        "rules": cmd_rules,
        "inspect": cmd_inspect,
        "help": cmd_help,
    }

    cmd_func = commands.get(args.command)
    if not cmd_func:
        print_error(f"Unknown command: {args.command}")
        return 1

    try:
        return cmd_func(ctx, args)
    except KeyboardInterrupt:
        print_error("Interrupted")
        return 130
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())