"""
Content transformation: scrambling and encryption.

This module performs the actual file transformations based on
RuleDecision instructions. It is intentionally dumb about policy
and filesystem traversal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .rules import RuleDecision
from .config import AES_NONCE_SIZE
from .utils import (
    chunk_bytes,
    shuffle_chunks,
    join_chunks,
    stable_hash,
    ensure_parent_dir,
)


@dataclass
class TransformMetadata:
    nonce: bytes
    tag: bytes
    chunk_order: List[int]


class Transformer:
    def __init__(self, key: bytes):
        self.key = key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def hide(self, path: Path, decision: RuleDecision) -> TransformMetadata:
        """
        Scramble and encrypt a file in-place.
        Returns metadata required for restoration.
        """

        data = path.read_bytes()

        chunks = chunk_bytes(data, decision.chunk_size)
        order = list(range(len(chunks)))

        if decision.scramble:
            shuffled = list(zip(order, chunks))
            shuffled = shuffle_chunks(shuffled)
            order, chunks = zip(*shuffled)
            chunks = list(chunks)
            order = list(order)

        payload = join_chunks(chunks)

        if decision.encrypt:
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=get_random_bytes(AES_NONCE_SIZE))
            ciphertext, tag = cipher.encrypt_and_digest(payload)
            output = cipher.nonce + tag + ciphertext
        else:
            output = payload
            tag = b""
            cipher = None

        ensure_parent_dir(path)
        path.write_bytes(output)

        return TransformMetadata(
            nonce=cipher.nonce if cipher else b"",
            tag=tag,
            chunk_order=order,
        )

    def reveal(self, path: Path, meta: TransformMetadata, decision: RuleDecision) -> None:
        """
        Restore a previously hidden file using stored metadata.
        """

        data = path.read_bytes()

        if decision.encrypt:
            nonce = data[:AES_NONCE_SIZE]
            tag = data[AES_NONCE_SIZE:AES_NONCE_SIZE + 16]
            ciphertext = data[AES_NONCE_SIZE + 16:]
            cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
            payload = cipher.decrypt_and_verify(ciphertext, tag)
        else:
            payload = data

        chunks = chunk_bytes(payload, decision.chunk_size)

        if decision.scramble:
            restored = [None] * len(chunks)
            for idx, original_index in enumerate(meta.chunk_order):
                restored[original_index] = chunks[idx]
            chunks = restored

        ensure_parent_dir(path)
        path.write_bytes(join_chunks(chunks))
