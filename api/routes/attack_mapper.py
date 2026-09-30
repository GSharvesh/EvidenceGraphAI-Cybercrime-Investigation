"""ATT&CK Mapper API routes for EvidenceGraphAI Phase 3."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from core.agents.attack_mapper.mapper import ATTACKMapper
from core.logging.logger import get_logger

logger = get_logger("api.routes.attack_mapper")
router = APIRouter(prefix="/attack", tags=["attack-mapper"])


class MappingRequest(BaseModel):
    """Request body for POST /attack/map."""

    evidence_id: str
    text: str
    session_id: str | None = None
    actor: str = "attack_mapper"


@router.post(
    "/map",
    summary="Map evidence text to ATT&CK techniques",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
)
def map_evidence(body: MappingRequest) -> list[dict[str, Any]]:
    """Applies rule-based ATT&CK mapping to the provided evidence text.

    Returns a list of technique mappings with confidence scores.
    Also creates MAPS_TO edges in Neo4j and persists records in PostgreSQL.
    """
    try:
        mapper = ATTACKMapper()
        results = mapper.map_text(
            text=body.text,
            evidence_id=body.evidence_id,
            session_id=body.session_id,
            actor=body.actor,
        )
        return [r.model_dump() for r in results]
    except Exception as exc:
        logger.error("ATT&CK mapping failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Mapping error: {exc}") from exc
