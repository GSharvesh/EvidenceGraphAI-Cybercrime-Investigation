"""Ontology loader and validation module for EvidenceGraphAI."""

from core.ontology.loader import OntologyLoader, load_ontology_schema
from core.ontology.validator import OntologyValidator

__all__ = ["OntologyLoader", "OntologyValidator", "load_ontology_schema"]
