"""
Content transformation: scrambling, encryption, and restoration.

This module is the heart of the tool. It performs:
- Scrambling (chunk permutation)
- Encryption (AES-GCM)
- Decryption + unscrambling
- Metadata embedding and extraction

Key design principles:
- Each encrypted file is self-contained
- Metadata is embedded inside the encrypted payload
- Scrambling is applied BEFORE encryption
- No external state files
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .config import AES_NONCE_SIZE, AES_TAG_SIZE, DEFAULT_CHUNK_SIZE
from .utils import chunk_bytes, join_chunks, shuffle_chunks, stable_hash


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ScrambleMetadata:
    """
    Metadata required to reverse scrambling.
    This is embedded inside the encrypted payload.
    """
    chunk_size: int
    permutation: List[int]  # Maps scrambled position -> original position
    original_size: int
    chunk_lengths: List[int]  # Length of each scrambled chunk

    def to_bytes(self) -> bytes:
        """Serialize metadata to bytes."""
        data = {
            "chunk_size": self.chunk_size,
            "permutation": self.permutation,
            "original_size": self.original_size,
            "chunk_lengths": self.chunk_lengths,
        }
        return json.dumps(data).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "ScrambleMetadata":
        """Deserialize metadata from bytes."""
        obj = json.loads(data.decode("utf-8"))
        return cls(
            chunk_size=obj["chunk_size"],
            permutation=obj["permutation"],
            original_size=obj["original_size"],
            chunk_lengths=obj["chunk_lengths"],
        )


@dataclass
class EncryptedPayload:
    """
    Complete encrypted file structure.

    Format:
        [4 bytes: metadata_length]
        [N bytes: encrypted_metadata]
        [M bytes: encrypted_content]
    """
    metadata: ScrambleMetadata
    encrypted_metadata: bytes
    encrypted_content: bytes
    nonce_metadata: bytes
    nonce_content: bytes

    def to_bytes(self) -> bytes:
        """
        Serialize the complete payload to bytes.

        Structure:
            [4 bytes: metadata_length]
            [12 bytes: nonce_metadata]
            [N bytes: encrypted_metadata]
            [12 bytes: nonce_content]
            [M bytes: encrypted_content]
        """
        metadata_length = len(self.encrypted_metadata)

        # Pack: metadata length (4 bytes, big-endian unsigned int)
        header = struct.pack(">I", metadata_length)

        return (
            header +
            self.nonce_metadata +
            self.encrypted_metadata +
            self.nonce_content +
            self.encrypted_content
        )

    @classmethod
    def from_bytes(cls, data: bytes, key: bytes) -> "EncryptedPayload":
        """
        Deserialize and decrypt payload from bytes.

        This performs decryption to extract metadata but does NOT
        unscramble the content yet.
        """
        if len(data) < 4:
            raise ValueError("Invalid encrypted payload: too short")

        # Unpack metadata length
        metadata_length = struct.unpack(">I", data[:4])[0]
        offset = 4

        # Extract nonce for metadata
        if len(data) < offset + AES_NONCE_SIZE:
            raise ValueError("Invalid encrypted payload: missing metadata nonce")
        nonce_metadata = data[offset:offset + AES_NONCE_SIZE]
        offset += AES_NONCE_SIZE

        # Extract encrypted metadata
        if len(data) < offset + metadata_length:
            raise ValueError("Invalid encrypted payload: incomplete metadata")
        encrypted_metadata = data[offset:offset + metadata_length]
        offset += metadata_length

        # Extract nonce for content
        if len(data) < offset + AES_NONCE_SIZE:
            raise ValueError("Invalid encrypted payload: missing content nonce")
        nonce_content = data[offset:offset + AES_NONCE_SIZE]
        offset += AES_NONCE_SIZE

        # Extract encrypted content
        encrypted_content = data[offset:]

        # Decrypt metadata
        aesgcm = AESGCM(key)
        try:
            metadata_bytes = aesgcm.decrypt(nonce_metadata, encrypted_metadata, None)
        except InvalidTag:
            raise ValueError("Decryption failed: invalid key or corrupted metadata")

        metadata = ScrambleMetadata.from_bytes(metadata_bytes)

        return cls(
            metadata=metadata,
            encrypted_metadata=encrypted_metadata,
            encrypted_content=encrypted_content,
            nonce_metadata=nonce_metadata,
            nonce_content=nonce_content,
        )


# ---------------------------------------------------------------------------
# Transformer class
# ---------------------------------------------------------------------------


class Transformer:
    """
    Handles scrambling, encryption, decryption, and unscrambling.
    """

    def __init__(self, key: bytes, deterministic: bool = False):
        """
        Initialize transformer.

        Args:
            key: 32-byte encryption key
            deterministic: if True, scrambling is deterministic (for stable diffs)
        """
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")

        self.key = key
        self.deterministic = deterministic
        self.aesgcm = AESGCM(key)

    # -----------------------------------------------------------------------
    # High-level API
    # -----------------------------------------------------------------------

    def hide_file(
        self,
        path: Path,
        output_path: Path,
        scramble: bool = True,
        encrypt: bool = True,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> None:
        """
        Scramble and encrypt a file, writing to output_path.

        Args:
            path: source file
            output_path: destination for encrypted file
            scramble: whether to scramble content
            encrypt: whether to encrypt content
            chunk_size: size of chunks for scrambling
        """
        content = path.read_bytes()
        transformed = self.hide(content, scramble, encrypt, chunk_size)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(transformed)

    def reveal_file(
        self,
        path: Path,
        output_path: Path,
    ) -> None:
        """
        Decrypt and unscramble a file, writing to output_path.

        Args:
            path: encrypted file
            output_path: destination for restored file
        """
        encrypted_content = path.read_bytes()
        restored = self.reveal(encrypted_content)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(restored)

    def hide(
        self,
        content: bytes,
        scramble: bool = True,
        encrypt: bool = True,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> bytes:
        """
        Transform content: scramble + encrypt.

        Args:
            content: original file content
            scramble: whether to scramble
            encrypt: whether to encrypt
            chunk_size: scrambling chunk size

        Returns:
            bytes: transformed content
        """
        if not scramble and not encrypt:
            # Nothing to do
            return content

        if scramble:
            scrambled, metadata = self._scramble(content, chunk_size)
        else:
            scrambled = content
            # Create dummy metadata for non-scrambled files
            chunks = chunk_bytes(content, chunk_size)
            metadata = ScrambleMetadata(
                chunk_size=chunk_size,
                permutation=list(range(len(chunks))),
                original_size=len(content),
                chunk_lengths=[len(c) for c in chunks],
            )

        if encrypt:
            return self._encrypt(scrambled, metadata)
        else:
            # If no encryption, just return scrambled content
            # (in practice, this mode is rarely used)
            return scrambled

    def reveal(self, encrypted_content: bytes) -> bytes:
        """
        Restore content: decrypt + unscramble.

        Args:
            encrypted_content: encrypted payload

        Returns:
            bytes: original content
        """
        payload = EncryptedPayload.from_bytes(encrypted_content, self.key)
        scrambled_content = self._decrypt_content(payload)
        original_content = self._unscramble(scrambled_content, payload.metadata)
        return original_content

    def read_metadata(self, encrypted_content: bytes) -> ScrambleMetadata:
        """
        Read metadata without decrypting content.

        Args:
            encrypted_content: encrypted payload

        Returns:
            ScrambleMetadata
        """
        payload = EncryptedPayload.from_bytes(encrypted_content, self.key)
        return payload.metadata

    # -----------------------------------------------------------------------
    # Scrambling logic
    # -----------------------------------------------------------------------

    def _scramble(
        self,
        content: bytes,
        chunk_size: int,
    ) -> Tuple[bytes, ScrambleMetadata]:
        """
        Scramble content by permuting chunks.

        Args:
            content: original content
            chunk_size: size of each chunk

        Returns:
            (scrambled_bytes, metadata)
        """
        if len(content) == 0:
            # Empty file edge case
            return content, ScrambleMetadata(
                chunk_size=chunk_size,
                permutation=[],
                original_size=0,
                chunk_lengths=[],
            )

        chunks = chunk_bytes(content, chunk_size)
        num_chunks = len(chunks)

        if self.deterministic:
            # Deterministic scrambling based on content hash
            permutation = self._deterministic_permutation(content, num_chunks)
        else:
            # Random scrambling - generate random permutation
            import random
            permutation = list(range(num_chunks))
            random.shuffle(permutation)

        # Apply permutation
        scrambled_chunks = [chunks[i] for i in permutation]
        scrambled_content = join_chunks(scrambled_chunks)

        # Build inverse permutation (scrambled_index -> original_index)
        # permutation[i] tells us: scrambled[i] = original[permutation[i]]
        # So the permutation itself IS the inverse mapping!
        # But let's keep it clear: inverse[scrambled_idx] = original_idx
        inverse_permutation = permutation  # This is already scrambled_idx -> original_idx

        # Save the length of each scrambled chunk for proper reconstruction
        chunk_lengths = [len(c) for c in scrambled_chunks]

        metadata = ScrambleMetadata(
            chunk_size=chunk_size,
            permutation=inverse_permutation,
            original_size=len(content),
            chunk_lengths=chunk_lengths,
        )

        return scrambled_content, metadata

    def _deterministic_permutation(self, content: bytes, num_chunks: int) -> List[int]:
        """
        Generate a deterministic permutation based on content hash.

        This allows scrambling to be stable across multiple runs,
        which is useful for clean diffs.
        """
        import random
        seed = int.from_bytes(stable_hash(content)[:4], byteorder="big")
        rng = random.Random(seed)
        indices = list(range(num_chunks))
        rng.shuffle(indices)
        return indices

    def _unscramble(
        self,
        scrambled_content: bytes,
        metadata: ScrambleMetadata,
    ) -> bytes:
        """
        Reverse scrambling using metadata.

        Args:
            scrambled_content: scrambled bytes
            metadata: scrambling metadata

        Returns:
            bytes: original content
        """
        if len(scrambled_content) == 0:
            return scrambled_content

        # Split scrambled content using the saved chunk lengths
        scrambled_chunks = []
        offset = 0
        for length in metadata.chunk_lengths:
            scrambled_chunks.append(scrambled_content[offset:offset + length])
            offset += length

        # metadata.permutation: scrambled_index -> original_index
        # We need to put each scrambled chunk back to its original position
        original_chunks = [None] * len(scrambled_chunks)
        for scrambled_idx, original_idx in enumerate(metadata.permutation):
            original_chunks[original_idx] = scrambled_chunks[scrambled_idx]

        original_content = join_chunks(original_chunks)

        # Trim to original size (handles padding edge cases)
        return original_content[:metadata.original_size]

    # -----------------------------------------------------------------------
    # Encryption logic
    # -----------------------------------------------------------------------

    def _encrypt(
        self,
        content: bytes,
        metadata: ScrambleMetadata,
    ) -> bytes:
        """
        Encrypt content and metadata using AES-GCM.

        Args:
            content: (possibly scrambled) content
            metadata: scrambling metadata

        Returns:
            bytes: complete encrypted payload
        """
        # Generate nonces
        if self.deterministic:
            # Deterministic nonces (derived from content)
            nonce_metadata = stable_hash(b"metadata" + content)[:AES_NONCE_SIZE]
            nonce_content = stable_hash(b"content" + content)[:AES_NONCE_SIZE]
        else:
            # Random nonces
            import os
            nonce_metadata = os.urandom(AES_NONCE_SIZE)
            nonce_content = os.urandom(AES_NONCE_SIZE)

        # Encrypt metadata
        metadata_bytes = metadata.to_bytes()
        encrypted_metadata = self.aesgcm.encrypt(nonce_metadata, metadata_bytes, None)

        # Encrypt content
        encrypted_content = self.aesgcm.encrypt(nonce_content, content, None)

        # Build payload
        payload = EncryptedPayload(
            metadata=metadata,
            encrypted_metadata=encrypted_metadata,
            encrypted_content=encrypted_content,
            nonce_metadata=nonce_metadata,
            nonce_content=nonce_content,
        )

        return payload.to_bytes()

    def _decrypt_content(self, payload: EncryptedPayload) -> bytes:
        """
        Decrypt content from payload.

        Args:
            payload: encrypted payload

        Returns:
            bytes: decrypted (but still scrambled) content
        """
        try:
            content = self.aesgcm.decrypt(
                payload.nonce_content,
                payload.encrypted_content,
                None
            )
        except InvalidTag:
            raise ValueError("Decryption failed: invalid key or corrupted content")

        return content


# ---------------------------------------------------------------------------
# Convenience functions
# ---------------------------------------------------------------------------


def hide_file(
    path: Path,
    output_path: Path,
    key: bytes,
    scramble: bool = True,
    encrypt: bool = True,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    deterministic: bool = False,
) -> None:
    """
    Convenience function to scramble and encrypt a file.
    """
    transformer = Transformer(key, deterministic=deterministic)
    transformer.hide_file(path, output_path, scramble, encrypt, chunk_size)


def reveal_file(
    path: Path,
    output_path: Path,
    key: bytes,
) -> None:
    """
    Convenience function to decrypt and unscramble a file.
    """
    transformer = Transformer(key)
    transformer.reveal_file(path, output_path)


def read_metadata(
    path: Path,
    key: bytes,
) -> ScrambleMetadata:
    """
    Convenience function to read metadata from an encrypted file.
    """
    transformer = Transformer(key)
    encrypted_content = path.read_bytes()
    return transformer.read_metadata(encrypted_content)