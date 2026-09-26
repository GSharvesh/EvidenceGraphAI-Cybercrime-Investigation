"""Ingestion subsystem domain exceptions for EvidenceGraphAI."""


class IngestionError(Exception):
    """Base exception for all ingestion-related errors."""

    pass


class UnsupportedFileTypeError(IngestionError):
    """Raised when an uploaded file is not in the list of supported forensic artifact formats."""

    pass


class InvalidFileError(IngestionError):
    """Raised when file content is corrupt, empty, or fails validation."""

    pass


class FileTooLargeError(IngestionError):
    """Raised when file size exceeds the configured maximum allowed threshold."""

    pass


class DuplicateArtifactError(IngestionError):
    """Raised when an artifact with the exact same SHA256 has already been ingested."""

    pass


class IngestionAtomicityError(IngestionError):
    """Raised when an ingestion step fails and cleanup or compensatory actions fail."""

    pass
