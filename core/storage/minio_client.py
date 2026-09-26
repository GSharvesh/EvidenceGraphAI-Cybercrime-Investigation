"""MinIO S3 object storage client wrapper for EvidenceGraphAI."""

import io
from pathlib import Path
from typing import Any, BinaryIO

from minio import Minio
from minio.error import S3Error

from core.config.settings import Settings, get_settings
from core.logging.logger import get_logger
from core.storage.exceptions import (
    ObjectNotFoundError,
    ObjectRetrievalError,
    ObjectUploadError,
    StorageConnectionError,
    StorageError,
)

logger = get_logger("core.storage.minio_client")


class MinioClient:
    """Wrapper around MinIO S3 SDK for secure, immutable forensic artifact storage."""

    def __init__(
        self,
        settings: Settings | None = None,
        client: Minio | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.bucket = self.settings.minio_bucket
        if client is not None:
            self._client = client
        else:
            self._client = Minio(
                endpoint=self.settings.minio_endpoint,
                access_key=self.settings.minio_access_key,
                secret_key=self.settings.minio_secret_key,
                secure=self.settings.minio_secure,
            )

    @property
    def raw_client(self) -> Minio:
        """Returns the underlying Minio client instance."""
        return self._client

    @staticmethod
    def get_artifact_object_name(evidence_id: str, sha256: str) -> str:
        """Generates deterministic object key for an evidence artifact."""
        return f"evidence/{evidence_id}/{sha256}"

    @staticmethod
    def get_manifest_object_name(manifest_id: str) -> str:
        """Generates deterministic object key for an Evidence Manifest."""
        return f"manifests/{manifest_id}.json"

    def ensure_bucket_exists(self, bucket_name: str | None = None) -> None:
        """Creates the bucket if it does not already exist."""
        target_bucket = bucket_name or self.bucket
        try:
            if not self._client.bucket_exists(target_bucket):
                self._client.make_bucket(target_bucket)
                logger.info("Created MinIO bucket", bucket=target_bucket)
        except Exception as exc:
            logger.error(
                "Failed to ensure MinIO bucket", bucket=target_bucket, error=str(exc)
            )
            raise StorageConnectionError(
                f"Failed to ensure bucket '{target_bucket}': {exc}"
            ) from exc

    def health_check(self) -> bool:
        """Checks if MinIO service is accessible and responsive."""
        try:
            self._client.bucket_exists(self.bucket)
            return True
        except Exception as exc:
            logger.debug("MinIO health check failed", error=str(exc))
            return False

    def put_object(
        self,
        evidence_id: str,
        sha256: str,
        data: bytes | BinaryIO | Path | str,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Uploads an evidence artifact to MinIO under an immutable object name.

        Args:
            evidence_id: Evidence identifier string.
            sha256: SHA256 digest string.
            data: File content as bytes, binary stream, or local path.
            content_type: MIME type string.
            metadata: Custom metadata key-value dictionary.

        Returns:
            MinIO URI string (e.g. minio://bucket/evidence/EV-123/hash).
        """
        self.ensure_bucket_exists()
        object_name = self.get_artifact_object_name(evidence_id, sha256)

        user_metadata: dict[str, str | list[str] | tuple[str]] = {
            "evidence-id": evidence_id,
            "sha256": sha256,
        }
        if metadata:
            for k, v in metadata.items():
                user_metadata[k.lower().replace("_", "-")] = str(v)

        try:
            if isinstance(data, str | Path):
                file_path = Path(data)
                if not file_path.exists():
                    raise ObjectUploadError(f"Local file does not exist: {file_path}")
                self._client.fput_object(
                    bucket_name=self.bucket,
                    object_name=object_name,
                    file_path=str(file_path),
                    content_type=content_type,
                    metadata=user_metadata,
                )
            elif isinstance(data, bytes):
                stream = io.BytesIO(data)
                self._client.put_object(
                    bucket_name=self.bucket,
                    object_name=object_name,
                    data=stream,
                    length=len(data),
                    content_type=content_type,
                    metadata=user_metadata,
                )
            else:
                # Seekable stream
                pos = data.tell()
                data.seek(0, io.SEEK_END)
                length = data.tell() - pos
                data.seek(pos, io.SEEK_SET)

                self._client.put_object(
                    bucket_name=self.bucket,
                    object_name=object_name,
                    data=data,
                    length=length,
                    content_type=content_type,
                    metadata=user_metadata,
                )

            storage_path = f"minio://{self.bucket}/{object_name}"
            logger.info("Uploaded artifact to storage", storage_path=storage_path)
            return storage_path

        except Exception as exc:
            logger.error(
                "Failed to upload object to MinIO",
                object_name=object_name,
                error=str(exc),
            )
            raise ObjectUploadError(
                f"Failed to upload object '{object_name}': {exc}"
            ) from exc

    def get_object(self, evidence_id: str, sha256: str) -> bytes:
        """Downloads artifact content from MinIO as raw bytes."""
        object_name = self.get_artifact_object_name(evidence_id, sha256)
        try:
            response = self._client.get_object(self.bucket, object_name)
            try:
                return response.read()
            finally:
                response.close()
                response.release_conn()
        except S3Error as exc:
            if exc.code in ("NoSuchKey", "NoSuchBucket"):
                raise ObjectNotFoundError(
                    f"Artifact object '{object_name}' not found: {exc}"
                ) from exc
            raise ObjectRetrievalError(
                f"Error reading artifact '{object_name}': {exc}"
            ) from exc
        except Exception as exc:
            logger.error(
                "Failed to retrieve object from MinIO",
                object_name=object_name,
                error=str(exc),
            )
            raise ObjectRetrievalError(
                f"Failed to read object '{object_name}': {exc}"
            ) from exc

    def object_exists(self, evidence_id: str, sha256: str) -> bool:
        """Checks if artifact object exists in storage."""
        object_name = self.get_artifact_object_name(evidence_id, sha256)
        try:
            self._client.stat_object(self.bucket, object_name)
            return True
        except S3Error as exc:
            if exc.code in ("NoSuchKey", "NoSuchBucket"):
                return False
            raise StorageError(f"Error checking object '{object_name}': {exc}") from exc
        except Exception:
            return False

    def get_object_metadata(self, evidence_id: str, sha256: str) -> dict[str, Any]:
        """Retrieves metadata and stat information for stored artifact."""
        object_name = self.get_artifact_object_name(evidence_id, sha256)
        try:
            stat = self._client.stat_object(self.bucket, object_name)
            return {
                "bucket_name": stat.bucket_name,
                "object_name": stat.object_name,
                "size": stat.size,
                "content_type": stat.content_type,
                "last_modified": (
                    stat.last_modified.isoformat() if stat.last_modified else None
                ),
                "etag": stat.etag,
                "version_id": stat.version_id,
                "metadata": stat.metadata or {},
            }
        except S3Error as exc:
            if exc.code in ("NoSuchKey", "NoSuchBucket"):
                raise ObjectNotFoundError(
                    f"Object '{object_name}' not found: {exc}"
                ) from exc
            raise ObjectRetrievalError(
                f"Error getting metadata for '{object_name}': {exc}"
            ) from exc
        except Exception as exc:
            raise ObjectRetrievalError(
                f"Failed to stat object '{object_name}': {exc}"
            ) from exc

    def put_manifest(self, manifest_id: str, manifest_json: str | bytes) -> str:
        """Uploads an Evidence Manifest JSON to MinIO."""
        self.ensure_bucket_exists()
        object_name = self.get_manifest_object_name(manifest_id)
        data_bytes = (
            manifest_json.encode("utf-8")
            if isinstance(manifest_json, str)
            else manifest_json
        )

        try:
            stream = io.BytesIO(data_bytes)
            self._client.put_object(
                bucket_name=self.bucket,
                object_name=object_name,
                data=stream,
                length=len(data_bytes),
                content_type="application/json",
                metadata={"manifest-id": manifest_id},
            )
            return f"minio://{self.bucket}/{object_name}"
        except Exception as exc:
            raise ObjectUploadError(
                f"Failed to store manifest '{manifest_id}': {exc}"
            ) from exc

    def get_manifest(self, manifest_id: str) -> bytes:
        """Retrieves stored Evidence Manifest content."""
        object_name = self.get_manifest_object_name(manifest_id)
        try:
            response = self._client.get_object(self.bucket, object_name)
            try:
                return response.read()
            finally:
                response.close()
                response.release_conn()
        except S3Error as exc:
            if exc.code in ("NoSuchKey", "NoSuchBucket"):
                raise ObjectNotFoundError(
                    f"Manifest '{manifest_id}' not found: {exc}"
                ) from exc
            raise ObjectRetrievalError(
                f"Error reading manifest '{manifest_id}': {exc}"
            ) from exc
        except Exception as exc:
            raise ObjectRetrievalError(
                f"Failed to read manifest '{manifest_id}': {exc}"
            ) from exc
