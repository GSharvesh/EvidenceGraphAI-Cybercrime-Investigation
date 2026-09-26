"""Cryptographic hashing utilities providing streaming, memory-safe SHA256 computation."""

import hashlib
from pathlib import Path
from typing import BinaryIO


def compute_sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> str:
    """Computes SHA256 digest from a binary stream in chunks.

    Args:
        stream: Readable binary stream.
        chunk_size: Read buffer size in bytes (default 64KB).

    Returns:
        Hex-encoded SHA256 string.
    """
    hasher = hashlib.sha256()
    while chunk := stream.read(chunk_size):
        hasher.update(chunk)
    return hasher.hexdigest()


def compute_sha256_file(file_path: Path | str, chunk_size: int = 65536) -> str:
    """Computes SHA256 digest of a file on disk using memory-safe streaming.

    Args:
        file_path: Path to the target file.
        chunk_size: Read buffer size in bytes (default 64KB).

    Returns:
        Hex-encoded SHA256 string.
    """
    path = Path(file_path)
    with open(path, "rb") as f:
        return compute_sha256_stream(f, chunk_size=chunk_size)


def compute_sha256_bytes(data: bytes) -> str:
    """Computes SHA256 digest of an in-memory bytes object.

    Args:
        data: Raw bytes.

    Returns:
        Hex-encoded SHA256 string.
    """
    return hashlib.sha256(data).hexdigest()
