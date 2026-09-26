"""Forensic artifact ingestion subsystem for EvidenceGraphAI."""

from core.ingestion.detector import (
    DetectedType,
    FileTypeDetectionResult,
    detect_file_type,
)
from core.ingestion.exceptions import (
    DuplicateArtifactError,
    FileTooLargeError,
    IngestionAtomicityError,
    IngestionError,
    InvalidFileError,
    UnsupportedFileTypeError,
)
from core.ingestion.hasher import (
    compute_sha256_bytes,
    compute_sha256_file,
    compute_sha256_stream,
)
from core.ingestion.ingestor import ArtifactIngestor, IngestResult
from core.ingestion.validators import (
    sanitize_filename,
    validate_allowed_type,
    validate_file_size,
)

__all__ = [
    "ArtifactIngestor",
    "IngestResult",
    "detect_file_type",
    "DetectedType",
    "FileTypeDetectionResult",
    "compute_sha256_bytes",
    "compute_sha256_file",
    "compute_sha256_stream",
    "sanitize_filename",
    "validate_file_size",
    "validate_allowed_type",
    "IngestionError",
    "UnsupportedFileTypeError",
    "InvalidFileError",
    "FileTooLargeError",
    "DuplicateArtifactError",
    "IngestionAtomicityError",
]
