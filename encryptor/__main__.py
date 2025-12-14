"""
Main entry point for running encryptor as a module.

Usage:
    python -m encryptor <command> [options]
"""

from .cli import main
import sys

if __name__ == "__main__":
    sys.exit(main())