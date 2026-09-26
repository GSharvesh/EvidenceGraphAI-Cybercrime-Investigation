"""Unit tests for MinIO S3 storage client wrapper."""

from unittest.mock import MagicMock

import pytest
from minio.error import S3Error

from core.config.settings import Settings
from core.storage.bucket_manager import BucketManager
from core.storage.exceptions import (
    ObjectNotFoundError,
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
    )
    assert uri.startswith("minio://")
    assert "evidence/EV-TEST-1/aabbccddeeff" in uri
    mock_minio_sdk.put_object.assert_called_once()


def test_get_object_success(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies downloading object bytes."""
    mock_resp = MagicMock()
    mock_resp.read.return_value = b"Downloaded Content"
    mock_minio_sdk.get_object.return_value = mock_resp

    data = storage_client.get_object("EV-1", "hash1")
    assert data == b"Downloaded Content"
    mock_resp.close.assert_called_once()


def test_get_object_not_found(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies ObjectNotFoundError on NoSuchKey."""
    err = S3Error(
        code="NoSuchKey",
        message="Object does not exist",
        resource="/evidence/EV-1/hash",
        request_id="1",
        host_id="1",
        response=MagicMock(),
    )
    mock_minio_sdk.get_object.side_effect = err

    with pytest.raises(ObjectNotFoundError):
        storage_client.get_object("EV-1", "hash1")


def test_object_exists(storage_client: MinioClient, mock_minio_sdk: MagicMock) -> None:
    """Verifies object_exists returns True when stat succeeds."""
    mock_minio_sdk.stat_object.return_value = MagicMock()
    assert storage_client.object_exists("EV-1", "hash1") is True

    err = S3Error(
        code="NoSuchKey",
        message="Not found",
        resource="r",
        request_id="1",
        host_id="1",
        response=MagicMock(),
    )
    mock_minio_sdk.stat_object.side_effect = err
    assert storage_client.object_exists("EV-1", "hash1") is False


def test_bucket_manager_enable_versioning(
    storage_client: MinioClient, mock_minio_sdk: MagicMock
) -> None:
    """Verifies BucketManager enables versioning on the bucket."""
    manager = BucketManager(storage_client=storage_client)
    manager.setup_artifact_storage()
    mock_minio_sdk.set_bucket_versioning.assert_called_once()
