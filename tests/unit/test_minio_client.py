"""Unit tests for MinIO S3 storage client wrapper."""

import io
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from minio.error import S3Error

from core.config.settings import Settings
from core.storage.bucket_manager import BucketManager
from core.storage.exceptions import (
    BucketCreationError,
    ObjectNotFoundError,
    ObjectRetrievalError,
    ObjectUploadError,
    StorageConnectionError,
)
from core.storage.minio_client import MinioClient


@pytest.fixture
def mock_minio_sdk() -> MagicMock:
    """Returns a mock Minio SDK instance."""
    client = MagicMock()
    client.bucket_exists.return_value = True
    return client


@pytest.fixture
def storage_client(mock_settings: Settings, mock_minio_sdk: MagicMock) -> MinioClient:
    """Returns a MinioClient instance with mocked underlying SDK."""
    return MinioClient(settings=mock_settings, client=mock_minio_sdk)


def test_ensure_bucket_creates_if_not_exists(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies make_bucket is called when bucket does not exist."""
    mock_minio_sdk.bucket_exists.return_value = False
    storage_client.ensure_bucket_exists("test-bucket")
    mock_minio_sdk.make_bucket.assert_called_once_with("test-bucket")


def test_ensure_bucket_error(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies StorageConnectionError raised on bucket creation failure."""
    mock_minio_sdk.bucket_exists.return_value = False
    mock_minio_sdk.make_bucket.side_effect = Exception("Permission denied")
    with pytest.raises(StorageConnectionError):
        storage_client.ensure_bucket_exists("bad-bucket")


def test_health_check(storage_client: MinioClient, mock_minio_sdk: MagicMock) -> None:
    """Verifies health check returns True on success and False on error."""
    mock_minio_sdk.bucket_exists.return_value = True
    assert storage_client.health_check() is True

    mock_minio_sdk.bucket_exists.side_effect = Exception("Connection refused")
    assert storage_client.health_check() is False


def test_put_object_bytes(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies uploading in-memory bytes."""
    data = b"Forensic PCAP Bytes"
    uri = storage_client.put_object(
        evidence_id="EV-TEST-1",
        sha256="aabbccddeeff",
        data=data,
        content_type="application/vnd.tcpdump.pcap",
        metadata={"custom": "tag"},
    )
    assert uri.startswith("minio://")
    assert "evidence/EV-TEST-1/aabbccddeeff" in uri
    mock_minio_sdk.put_object.assert_called_once()


def test_put_object_stream(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies uploading from a stream."""
    stream = io.BytesIO(b"Stream data content")
    uri = storage_client.put_object(
        evidence_id="EV-TEST-2",
        sha256="112233",
        data=stream,
        content_type="application/octet-stream",
    )
    assert "evidence/EV-TEST-2/112233" in uri
    mock_minio_sdk.put_object.assert_called_once()


def test_put_object_file_path(
    storage_client: MinioClient, mock_minio_sdk: MagicMock, tmp_path: Path
) -> None:
    """Verifies uploading from local file path."""
    tmp_file = tmp_path / "sample.bin"
    tmp_file.write_bytes(b"File data")

    uri = storage_client.put_object(
        evidence_id="EV-TEST-3",
        sha256="445566",
        data=tmp_file,
        content_type="application/octet-stream",
    )
    assert "evidence/EV-TEST-3/445566" in uri
    mock_minio_sdk.fput_object.assert_called_once()


def test_put_object_nonexistent_file(
    storage_client: MinioClient, tmp_path: Path
) -> None:
    """Verifies error raised when local file does not exist."""
    with pytest.raises(ObjectUploadError, match="Local file does not exist"):
        storage_client.put_object(
            evidence_id="EV-TEST",
            sha256="123",
            data=tmp_path / "nonexistent.bin",
        )


def test_put_object_upload_error(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies S3Error during put_object is translated to ObjectUploadError."""
    mock_minio_sdk.put_object.side_effect = Exception("S3 timeout")
    with pytest.raises(ObjectUploadError):
        storage_client.put_object(
            evidence_id="EV-TEST",
            sha256="123",
            data=b"data",
        )


def test_get_object_success(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies retrieving raw bytes from storage."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"Recovered artifact content"
    mock_minio_sdk.get_object.return_value = mock_resp

    data = storage_client.get_object("EV-TEST-1", "aabbccddeeff")
    assert data == b"Recovered artifact content"
    mock_resp.close.assert_called_once()
    mock_resp.release_conn.assert_called_once()


def test_get_object_not_found(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies ObjectNotFoundError raised when object is missing."""
    mock_s3_error = S3Error(
        code="NoSuchKey",
        message="Key not found",
        resource="/test",
        request_id="req",
        host_id="host",
        response=MagicMock(status=404),
    )
    mock_minio_sdk.get_object.side_effect = mock_s3_error

    with pytest.raises(ObjectNotFoundError):
        storage_client.get_object("EV-MISSING", "123456")


def test_get_object_retrieval_error(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies ObjectRetrievalError raised on general S3 error."""
    mock_minio_sdk.get_object.side_effect = Exception("Network dropped")

    with pytest.raises(ObjectRetrievalError):
        storage_client.get_object("EV-ERROR", "123456")


def test_object_exists(storage_client: MinioClient, mock_minio_sdk: MagicMock) -> None:
    """Verifies object_exists returns True when stat_object succeeds."""
    mock_minio_sdk.stat_object.return_value = MagicMock()
    assert storage_client.object_exists("EV-1", "sha1") is True

    mock_s3_error = S3Error(
        code="NoSuchKey",
        message="Not found",
        resource="/test",
        request_id="req",
        host_id="host",
        response=MagicMock(status=404),
    )
    mock_minio_sdk.stat_object.side_effect = mock_s3_error
    assert storage_client.object_exists("EV-1", "sha1") is False


def test_get_object_metadata(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies get_object_metadata returns metadata dict."""
    from datetime import UTC, datetime

    mock_stat = MagicMock()
    mock_stat.bucket_name = "test-bucket"
    mock_stat.object_name = "evidence/EV-1/sha1"
    mock_stat.size = 1024
    mock_stat.content_type = "application/json"
    mock_stat.last_modified = datetime(2026, 9, 26, 10, 0, 0, tzinfo=UTC)
    mock_stat.etag = "etag123"
    mock_stat.version_id = "v1"
    mock_stat.metadata = {"x-amz-meta-custom": "val"}
    mock_minio_sdk.stat_object.return_value = mock_stat

    meta = storage_client.get_object_metadata("EV-1", "sha1")
    assert meta["size"] == 1024
    assert meta["content_type"] == "application/json"
    assert "2026-09-26" in meta["last_modified"]


def test_put_and_get_manifest(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies storing and retrieving manifest JSON documents."""
    import json

    manifest_doc = {
        "manifest_id": "MANIFEST-001",
        "evidence_count": 1,
    }

    uri = storage_client.put_manifest("MANIFEST-001", json.dumps(manifest_doc))
    assert "manifests/MANIFEST-001.json" in uri

    mock_resp = MagicMock()
    mock_resp.read.return_value = (
        b'{"manifest_id": "MANIFEST-001", "evidence_count": 1}'
    )
    mock_minio_sdk.get_object.return_value = mock_resp

    retrieved_bytes = storage_client.get_manifest("MANIFEST-001")
    retrieved = json.loads(retrieved_bytes)
    assert retrieved["manifest_id"] == "MANIFEST-001"


def test_bucket_manager_setup(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies BucketManager initializes and configures versioning."""
    mgr = BucketManager(storage_client=storage_client)
    mgr.setup_artifact_storage()
    mock_minio_sdk.set_bucket_versioning.assert_called_once()


def test_get_object_metadata_errors(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies get_object_metadata error branches."""
    mock_s3_error = S3Error(
        code="NoSuchKey",
        message="Key not found",
        resource="/test",
        request_id="req",
        host_id="host",
        response=MagicMock(status=404),
    )
    mock_minio_sdk.stat_object.side_effect = mock_s3_error
    with pytest.raises(ObjectNotFoundError):
        storage_client.get_object_metadata("EV-1", "sha1")

    mock_s3_error_500 = S3Error(
        code="InternalError",
        message="Internal Error",
        resource="/test",
        request_id="req",
        host_id="host",
        response=MagicMock(status=500),
    )
    mock_minio_sdk.stat_object.side_effect = mock_s3_error_500
    with pytest.raises(ObjectRetrievalError):
        storage_client.get_object_metadata("EV-1", "sha1")

    mock_minio_sdk.stat_object.side_effect = RuntimeError("Crash")
    with pytest.raises(ObjectRetrievalError):
        storage_client.get_object_metadata("EV-1", "sha1")


def test_put_and_get_manifest_errors(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies put_manifest and get_manifest error handling."""
    mock_minio_sdk.put_object.side_effect = Exception("Write fail")
    with pytest.raises(ObjectUploadError):
        storage_client.put_manifest("MAN-1", "{}")

    mock_s3_error = S3Error(
        code="NoSuchKey",
        message="Key not found",
        resource="/test",
        request_id="req",
        host_id="host",
        response=MagicMock(status=404),
    )
    mock_minio_sdk.get_object.side_effect = mock_s3_error
    with pytest.raises(ObjectNotFoundError):
        storage_client.get_manifest("MAN-MISSING")

    mock_s3_error_500 = S3Error(
        code="InternalError",
        message="Internal Error",
        resource="/test",
        request_id="req",
        host_id="host",
        response=MagicMock(status=500),
    )
    mock_minio_sdk.get_object.side_effect = mock_s3_error_500
    with pytest.raises(ObjectRetrievalError):
        storage_client.get_manifest("MAN-ERROR")

    mock_minio_sdk.get_object.side_effect = RuntimeError("Crash")
    with pytest.raises(ObjectRetrievalError):
        storage_client.get_manifest("MAN-CRASH")


def test_object_exists_exceptions(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies object_exists behavior under various S3 and network exceptions."""
    mock_s3_error_500 = S3Error(
        code="InternalError",
        message="Internal Error",
        resource="/test",
        request_id="req",
        host_id="host",
        response=MagicMock(status=500),
    )
    mock_minio_sdk.stat_object.side_effect = mock_s3_error_500
    from core.storage.exceptions import StorageError

    with pytest.raises(StorageError):
        storage_client.object_exists("EV-1", "sha1")

    mock_minio_sdk.stat_object.side_effect = RuntimeError("Network partition")
    assert storage_client.object_exists("EV-1", "sha1") is False


def test_bucket_manager_errors(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies BucketManager error handling."""
    mock_minio_sdk.bucket_exists.side_effect = Exception("DB down")
    mgr = BucketManager(storage_client=storage_client)
    with pytest.raises(BucketCreationError):
        mgr.ensure_bucket("error-bucket")

    mock_minio_sdk.bucket_exists.side_effect = None
    mock_minio_sdk.bucket_exists.return_value = True
    mock_minio_sdk.set_bucket_versioning.side_effect = Exception("Not supported")
    # Should log warning without raising
    mgr.enable_versioning("test-bucket")
