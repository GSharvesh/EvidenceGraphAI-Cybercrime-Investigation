"""Storage subsystem domain exceptions for EvidenceGraphAI."""


class StorageError(Exception):
    """Base exception for all storage-related errors."""

    pass


class StorageConnectionError(StorageError):
    """Raised when connecting to MinIO/S3 fails."""

    pass


class BucketCreationError(StorageError):
    """Raised when creating or configuring a storage bucket fails."""

    pass


class ObjectNotFoundError(StorageError):
    """Raised when the requested object does not exist in storage."""

    pass


class ObjectUploadError(StorageError):
    """Raised when uploading an object to storage fails."""

    pass


class ObjectRetrievalError(StorageError):
    """Raised when reading or downloading an object fails."""

    pass
