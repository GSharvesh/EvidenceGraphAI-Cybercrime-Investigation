"""Validation utilities for forensic artifact uploads."""

import re
from pathlib import PureWindowsPath

from core.config.settings import Settings, get_settings
from core.ingestion.detector import DetectedType
from core.ingestion.exceptions import (
    FileTooLargeError,
    InvalidFileError,
    UnsupportedFileTypeError,
)


def sanitize_filename(filename: str) -> str:
    """Sanitizes filename preventing directory traversal and null byte injection.

    Args:
        filename: Raw user-supplied filename.

    Returns:
        Safe base filename string.
    """
    if not filename or not filename.strip():
        return "unnamed_artifact.bin"

    # Strip path components and null bytes cross-platform
    cleaned = filename.replace("\x00", "").strip()
    cleaned = PureWindowsPath(cleaned).name

    # Remove dangerous characters
    cleaned = re.sub(r"[^\w\.\-\_]", "_", cleaned)
    if not cleaned or not cleaned.strip("."):
        return "unnamed_artifact.bin"
    return cleaned


def validate_file_size(size_bytes: int, settings: Settings | None = None) -> None:
    """Validates that uploaded file size does not exceed the maximum allowed threshold.

    Args:
        size_bytes: File size in bytes.
        settings: Application settings.

    Raises:
        FileTooLargeError: If size exceeds maximum limit.
        InvalidFileError: If size is 0 or negative.
    """
    if size_bytes <= 0:
        raise InvalidFileError("Artifact file cannot be empty (0 bytes)")

    cfg = settings or get_settings()
    max_bytes = cfg.ingestion_max_file_size_mb * 1024 * 1024

    if size_bytes > max_bytes:
        raise FileTooLargeError(
            f"File size {size_bytes} bytes exceeds configured maximum limit of "
            f"{cfg.ingestion_max_file_size_mb} MB ({max_bytes} bytes)"
        )


def validate_allowed_type(
    detected_type: DetectedType | str, settings: Settings | None = None
) -> None:
    """Validates that the detected file type is permitted by configuration.

    Args:
        detected_type: Detected artifact type.
        settings: Application settings.

    Raises:
        UnsupportedFileTypeError: If type is unknown or not permitted.
    """
    type_str = (
        detected_type.value.lower()
        if isinstance(detected_type, DetectedType)
        else str(detected_type).lower()
    )

    if type_str == "unknown":
        raise UnsupportedFileTypeError(
            "Unsupported file format: content signature could not be recognized"
        )

    cfg = settings or get_settings()
    allowed_list = [
        t.strip().lower() for t in cfg.ingestion_allowed_types.split(",") if t.strip()
    ]

    # Normalize type matching
    type_aliases = {
        "pcap": {"pcap", "pcapng"},
        "json": {"json"},
        "pe": {"pe", "exe", "dll"},
        "elf": {"elf"},
        "apk": {"apk"},
        "plain_text": {"text", "plain_text", "log", "txt"},
        "pdf": {"pdf"},
        "cert_pem": {"cert_pem", "pem", "crt"},
        "cert_der": {"cert_der", "der"},
    }

    matching_set = {type_str}
    for canonical, aliases in type_aliases.items():
        if type_str == canonical or type_str in aliases:
            matching_set = {canonical} | aliases
            break

    is_allowed = any(item in allowed_list for item in matching_set)

    if not is_allowed:
        raise UnsupportedFileTypeError(
            f"File type '{detected_type}' is not allowed by current system configuration"
        )
