"""FastAPI dependency injection providers."""

from collections.abc import Generator

from fastapi import Depends
from structlog.stdlib import BoundLogger

from core.config.settings import Settings, get_settings
from core.custody.ledger import CustodyLedger
from core.custody.manifest import ManifestGenerator
from core.custody.verifier import ArtifactVerifier
from core.db.postgres import PostgresClient
from core.graph.client import GraphClient
from core.ingestion.ingestor import ArtifactIngestor
from core.logging.logger import get_logger
from core.storage.minio_client import MinioClient

_graph_client_instance: GraphClient | None = None
_postgres_client_instance: PostgresClient | None = None
_minio_client_instance: MinioClient | None = None


def get_app_settings() -> Settings:
    """Dependency provider for application settings."""
    return get_settings()


def get_app_logger() -> BoundLogger:
    """Dependency provider for structlog logger."""
    return get_logger("api")


def get_graph_client_instance(settings: Settings | None = None) -> GraphClient:
    """Returns singleton GraphClient instance without generator semantics."""
    global _graph_client_instance
    if _graph_client_instance is None:
        cfg = settings or get_settings()
        _graph_client_instance = GraphClient(settings=cfg)
    return _graph_client_instance


def get_graph_client(
    settings: Settings = Depends(get_app_settings),
) -> Generator[GraphClient, None, None]:
    """Dependency provider for Neo4j GraphClient instance."""
    yield get_graph_client_instance(settings=settings)


def get_postgres_client(
    settings: Settings = Depends(get_app_settings),
) -> PostgresClient:
    """Dependency provider for PostgreSQL client."""
    global _postgres_client_instance
    if _postgres_client_instance is None:
        _postgres_client_instance = PostgresClient(settings=settings)
    return _postgres_client_instance


def get_minio_client(
    settings: Settings = Depends(get_app_settings),
) -> MinioClient:
    """Dependency provider for MinIO storage client."""
    global _minio_client_instance
    if _minio_client_instance is None:
        _minio_client_instance = MinioClient(settings=settings)
    return _minio_client_instance


def get_custody_ledger(
    db: PostgresClient = Depends(get_postgres_client),
) -> CustodyLedger:
    """Dependency provider for CustodyLedger instance."""
    return CustodyLedger(db_client=db)


def get_artifact_verifier(
    storage: MinioClient = Depends(get_minio_client),
    ledger: CustodyLedger = Depends(get_custody_ledger),
) -> ArtifactVerifier:
    """Dependency provider for ArtifactVerifier instance."""
    return ArtifactVerifier(storage_client=storage, custody_ledger=ledger)


def get_manifest_generator(
    settings: Settings = Depends(get_app_settings),
    ledger: CustodyLedger = Depends(get_custody_ledger),
    storage: MinioClient = Depends(get_minio_client),
) -> ManifestGenerator:
    """Dependency provider for ManifestGenerator instance."""
    return ManifestGenerator(
        settings=settings, custody_ledger=ledger, storage_client=storage
    )


def get_artifact_ingestor(
    settings: Settings = Depends(get_app_settings),
    storage: MinioClient = Depends(get_minio_client),
    graph: GraphClient = Depends(get_graph_client),
    ledger: CustodyLedger = Depends(get_custody_ledger),
) -> ArtifactIngestor:
    """Dependency provider for ArtifactIngestor pipeline."""
    return ArtifactIngestor(
        settings=settings,
        storage_client=storage,
        graph_client=graph,
        custody_ledger=ledger,
    )
