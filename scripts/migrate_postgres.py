#!/usr/bin/env python3
"""PostgreSQL migration runner for EvidenceGraphAI.

Applies pending SQL migration files idempotently and records them in schema_migrations table.
"""

import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.db.postgres import PostgresClient
from core.logging.logger import configure_logging, get_logger

configure_logging(log_level="INFO", is_json=False)
logger = get_logger("scripts.migrate_postgres")


def apply_migrations(client: PostgresClient | None = None) -> None:
    """Discovers and applies pending database migrations."""
    db = client or PostgresClient()
    logger.info("Starting PostgreSQL database migration...")

    # Ensure migrations tracking table exists
    create_tracking_table_sql = """
    CREATE TABLE IF NOT EXISTS schema_migrations (
        id SERIAL PRIMARY KEY,
        migration_name VARCHAR(255) UNIQUE NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    """
    db.execute(create_tracking_table_sql)

    applied_rows = db.fetch_all("SELECT migration_name FROM schema_migrations")
    applied_names = {row["migration_name"] for row in applied_rows}

    migrations_dir = Path(__file__).parent.parent / "core" / "db" / "migrations"
    migration_files = sorted(migrations_dir.glob("*.sql"))

    if not migration_files:
        logger.info(
            "No migration SQL files found in directory", dir=str(migrations_dir)
        )
        return

    for sql_file in migration_files:
        name = sql_file.name
        if name in applied_names:
            logger.debug("Migration already applied, skipping", migration=name)
            continue

        logger.info("Applying migration", migration=name)
        sql_content = sql_file.read_text(encoding="utf-8")

        with db.get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql_content)
                cur.execute(
                    "INSERT INTO schema_migrations (migration_name) VALUES (%s)",
                    (name,),
                )
            conn.commit()

        logger.info("Successfully applied migration", migration=name)

    logger.info("PostgreSQL migration completed successfully.")


if __name__ == "__main__":
    try:
        apply_migrations()
        sys.exit(0)
    except Exception as exc:
        logger.error("Migration failed", error=str(exc))
        sys.exit(1)
