"""Unit tests for forensic artifact upload validation utilities."""

import pytest

from core.config.settings import Settings
from core.ingestion.detector import DetectedType
from core.ingestion.exceptions import (
    FileTooLargeError,
    InvalidFileError,
    UnsupportedFileTypeError,
)
from core.ingestion.validators import (
    sanitize_filename,
    validate_allowed_type,
    validate_file_size,
)


def test_sanitize_filename_standard() -> None:
    """Verifies normal safe filenames are preserved."""
    assert sanitize_filename("capture.pcap") == "capture.pcap"
    assert sanitize_filename("sample_artifact-2026.json") == "sample_artifact-2026.json"


def test_sanitize_filename_traversal_and_null_bytes() -> None:
    """Verifies directory traversal paths and null bytes are stripped."""
    assert sanitize_filename("../../etc/passwd\x00.exe") == "passwd.exe"
    assert sanitize_filename("..\\..\\windows\\system32\\cmd.exe") == "cmd.exe"
    assert sanitize_filename("C:/Users/test/Documents/log.txt") == "log.txt"


def test_sanitize_filename_dangerous_characters() -> None:
    """Verifies special characters are replaced with underscores."""
    assert sanitize_filename("evil;rm -rf *$.pcap") == "evil_rm_-rf___.pcap"
    assert sanitize_filename("payload<script>.json") == "payload_script_.json"


def test_sanitize_filename_empty_or_whitespace() -> None:
    """Verifies empty strings fall back to unnamed_artifact.bin."""
    assert sanitize_filename("") == "unnamed_artifact.bin"
    assert sanitize_filename("   ") == "unnamed_artifact.bin"
    assert sanitize_filename("\x00\x00") == "unnamed_artifact.bin"


def test_validate_file_size_valid() -> None:
    """Verifies valid file sizes pass without exception."""
    validate_file_size(1024)
    validate_file_size(10 * 1024 * 1024)


def test_validate_file_size_empty_or_negative() -> None:
    """Verifies 0 or negative sizes raise InvalidFileError."""
    with pytest.raises(InvalidFileError, match="cannot be empty"):
        validate_file_size(0)

    with pytest.raises(InvalidFileError, match="cannot be empty"):
        validate_file_size(-100)


def test_validate_file_size_exceeds_limit() -> None:
    """Verifies size exceeding configured limit raises FileTooLargeError."""
    settings = Settings(ingestion_max_file_size_mb=10)
    with pytest.raises(FileTooLargeError, match="exceeds configured maximum limit"):
        validate_file_size(11 * 1024 * 1024, settings=settings)


def test_validate_allowed_type_supported() -> None:
    """Verifies allowed types and aliases pass validation."""
    validate_allowed_type(DetectedType.PCAP)
    validate_allowed_type(DetectedType.JSON)
    validate_allowed_type(DetectedType.PE)
    validate_allowed_type(DetectedType.APK)
    validate_allowed_type(DetectedType.PLAIN_TEXT)
    validate_allowed_type(DetectedType.CERT_PEM)
    validate_allowed_type(DetectedType.CERT_DER)
    validate_allowed_type("pcapng")
    validate_allowed_type("exe")


def test_validate_allowed_type_unknown() -> None:
    """Verifies unknown type raises UnsupportedFileTypeError."""
    with pytest.raises(UnsupportedFileTypeError, match="could not be recognized"):
        validate_allowed_type(DetectedType.UNKNOWN)

    with pytest.raises(UnsupportedFileTypeError, match="could not be recognized"):
        validate_allowed_type("UNKNOWN")


def test_validate_allowed_type_disallowed() -> None:
    """Verifies disallowed types raise UnsupportedFileTypeError."""
    settings = Settings(ingestion_allowed_types="pcap,json")
    with pytest.raises(
        UnsupportedFileTypeError, match="not allowed by current system configuration"
    ):
        validate_allowed_type(DetectedType.PE, settings=settings)
