"""
Global configuration and environment handling.

This module is responsible for:
- Loading secrets (encryption key) from the environment
- Defining global constants and defaults
- Providing normalized, ready-to-use configuration values

Nothing in this file should depend on:
- the filesystem
- the manifest structure
- rule evaluation
- CLI arguments

If something here changes, the *entire tool* behavior changes.
"""

from __future__ import annotations

import os
import hashlib
from typing import Final

# ---------------------------------------------------------------------------
# Tool / format versioning
# ---------------------------------------------------------------------------

SUPPORTED_MANIFEST_VERSION: Final[int] = 1
TOOL_VERSION: Final[str] = "0.1.0"

# ---------------------------------------------------------------------------
# Default behavior
# ---------------------------------------------------------------------------

DEFAULT_CHUNK_SIZE: Final[int] = 64
DEFAULT_PROFILE: Final[str] = "default"

# AES-GCM defaults
AES_NONCE_SIZE: Final[int] = 12
AES_TAG_SIZE: Final[int] = 16

# ---------------------------------------------------------------------------
# Environment variable names
# ---------------------------------------------------------------------------

ENV_ENCRYPTION_KEY: Final[str] = "ENCRYPTION_KEY"
ENV_MODE: Final[str] = "ENCRYPTOR_MODE"  # e.g. dev / prod

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_encryption_key() -> bytes:
    """
    Load and normalize the encryption key from the environment.

    The raw value is hashed to ensure a fixed-length key suitable
    for symmetric encryption algorithms.

    Raises:
        RuntimeError: if the key is missing

    Returns:
        bytes: 32-byte derived key
    """

    raw = os.getenv(ENV_ENCRYPTION_KEY)
    if not raw:
        raise RuntimeError(
            f"Missing required environment variable: {ENV_ENCRYPTION_KEY}"
        )

    # Normalize key length using SHA-256
    return hashlib.sha256(raw.encode("utf-8")).digest()



def get_execution_mode() -> str:
    """
    Return the current execution mode.

    This can be used to slightly alter behavior between environments
    (e.g. dev vs CI), but should never bypass security controls silently.

    Returns:
        str: execution mode name
    """

    return os.getenv(ENV_MODE, "prod")
