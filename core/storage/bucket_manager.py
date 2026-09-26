"""MinIO bucket management, versioning configuration, and immutability controls."""

from minio.commonconfig import ENABLED
from minio.versioningconfig import VersioningConfig

from core.logging.logger import get_logger
from core.storage.exceptions import BucketCreationError
from core.storage.minio_client import MinioClient

logger = get_logger("core.storage.bucket_manager")


class BucketManager:
    """Manages S3 bucket lifecycle, versioning, and security policies."""

    def __init__(self, storage_client: MinioClient | None = None) -> None:
        self.storage = storage_client or MinioClient()

    def ensure_bucket(self, bucket_name: str | None = None) -> None:
        """Ensures that the artifact bucket exists."""
        target_bucket = bucket_name or self.storage.bucket
        try:
            self.storage.ensure_bucket_exists(target_bucket)
        except Exception as exc:
            raise BucketCreationError(
                f"Failed to create bucket '{target_bucket}': {exc}"
            ) from exc

    def enable_versioning(self, bucket_name: str | None = None) -> None:
        """Enables object versioning on the target bucket for forensic auditability."""
        target_bucket = bucket_name or self.storage.bucket
        self.ensure_bucket(target_bucket)
        try:
            config = VersioningConfig(ENABLED)
            self.storage.raw_client.set_bucket_versioning(target_bucket, config)
            logger.info("Enabled bucket versioning", bucket=target_bucket)
        except Exception as exc:
            logger.warning(
                "Could not set bucket versioning (may not be supported in standalone mode)",
                bucket=target_bucket,
                error=str(exc),
            )

    def setup_artifact_storage(self, bucket_name: str | None = None) -> None:
        """Complete initial setup for artifact storage bucket."""
        target_bucket = bucket_name or self.storage.bucket
        self.ensure_bucket(target_bucket)
        self.enable_versioning(target_bucket)
        logger.info("Artifact storage bucket setup complete", bucket=target_bucket)
