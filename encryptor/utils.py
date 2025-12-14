"""
Shared utility helpers.

This module contains small, reusable helpers that do not belong
to business logic, rule evaluation, or encryption orchestration.
"""

from __future__ import annotations

import hashlib
import os
import random
import string
from pathlib import Path
from typing import Iterable, List


# ---------------------------------------------------------------------------
# Hashing / identifiers
# ---------------------------------------------------------------------------


def stable_hash(data: bytes) -> bytes:
    """Return a stable SHA-256 hash of arbitrary bytes."""
    return hashlib.sha256(data).digest()


def short_hash(data: bytes, length: int = 8) -> str:
    """Return a short hex hash useful for filenames or IDs."""
    return hashlib.sha256(data).hexdigest()[:length]


# ---------------------------------------------------------------------------
# Randomization / scrambling helpers
# ---------------------------------------------------------------------------


def random_string(length: int = 12) -> str:
    """Generate a random alphanumeric string."""
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def shuffle_chunks(chunks: List[bytes]) -> List[bytes]:
    """Return a new list of chunks in randomized order."""
    shuffled = chunks[:]
    random.shuffle(shuffled)
    return shuffled


# ---------------------------------------------------------------------------
# Byte helpers
# ---------------------------------------------------------------------------


def chunk_bytes(data: bytes, size: int) -> List[bytes]:
    """Split bytes into fixed-size chunks."""
    return [data[i : i + size] for i in range(0, len(data), size)]


def join_chunks(chunks: Iterable[bytes]) -> bytes:
    """Join chunks back into a single byte sequence."""
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# Filesystem helpers
# ---------------------------------------------------------------------------


def is_binary_file(path: Path, sample_size: int = 1024) -> bool:
    """Heuristically determine whether a file is binary."""
    try:
        with path.open("rb") as fh:
            sample = fh.read(sample_size)
        return b"\x00" in sample
    except OSError:
        return False


def ensure_parent_dir(path: Path) -> None:
    """Ensure the parent directory of a file exists."""
    path.parent.mkdir(parents=True, exist_ok=True)