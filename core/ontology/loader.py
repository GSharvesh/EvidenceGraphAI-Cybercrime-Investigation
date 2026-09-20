"""Loader for parsing schema.yaml into Python dictionary structures."""

from pathlib import Path
from typing import Any

import yaml


class OntologyLoader:
    """Loads and caches the EvidenceGraphAI YAML ontology schema."""

    def __init__(self, schema_path: Path | str | None = None) -> None:
        if schema_path is None:
            schema_path = Path(__file__).parent / "schema.yaml"
        self.schema_path = Path(schema_path)
        self._schema: dict[str, Any] | None = None

    def load(self) -> dict[str, Any]:
        """Loads and returns the schema dict.

        Returns:
            Dict containing nodes and relationships schema definitions.
        """
        if self._schema is None:
            if not self.schema_path.exists():
                raise FileNotFoundError(
                    f"Ontology schema not found at {self.schema_path}"
                )
            with open(self.schema_path, encoding="utf-8") as f:
                self._schema = yaml.safe_load(f)
        return self._schema or {}

    @property
    def node_types(self) -> list[str]:
        """Returns list of valid node type names."""
        schema = self.load()
        return list(schema.get("nodes", {}).keys())

    @property
    def relationship_types(self) -> list[str]:
        """Returns list of valid relationship type names."""
        schema = self.load()
        return list(schema.get("relationships", {}).keys())


def load_ontology_schema(schema_path: Path | str | None = None) -> dict[str, Any]:
    """Helper function to quickly load ontology schema."""
    return OntologyLoader(schema_path).load()
