"""Unit tests for streaming cryptographic SHA256 hasher."""

import hashlib
import io
from pathlib import Path

from core.ingestion.hasher import (
    compute_sha256_bytes,
    compute_sha256_file,
    compute_sha256_stream,
)


def test_compute_sha256_bytes_known_vector() -> None:
    """Tests SHA256 computation against standard NIST/RFC test vectors."""
    # NIST vector: "" (empty string)
    assert (
        compute_sha256_bytes(b"")
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )

    # NIST vector: "abc"
    assert (
        compute_sha256_bytes(b"abc")
        == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_compute_sha256_stream() -> None:
    """Verifies streaming SHA256 matches in-memory calculation on multi-chunk payload."""
    payload = b"EvidenceGraphAI Forensic Artifact Test Payload " * 5000  # ~240KB
    expected = hashlib.sha256(payload).hexdigest()

    stream = io.BytesIO(payload)
    result = compute_sha256_stream(stream, chunk_size=4096)
    assert result == expected


def test_compute_sha256_file(tmp_path: Path) -> None:
    """Verifies file on disk SHA256 computation."""
    test_file = tmp_path / "forensic_test.dat"
    content = b"Forensic Investigation Chain of Custody 2026"
    test_file.write_bytes(content)

    expected = hashlib.sha256(content).hexdigest()
    assert compute_sha256_file(test_file) == expected
