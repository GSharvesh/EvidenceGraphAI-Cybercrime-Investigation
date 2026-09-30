"""Sandbox Replay API routes for EvidenceGraphAI Phase 3."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from core.agents.sandbox_replay.agent import SandboxReplayAgent
from core.agents.threat_reconstruction.agent import ThreatReconstructionAgent
from core.agents.threat_reconstruction.exceptions import CVENotAnalyzedError
from core.db.postgres import PostgresClient
from core.logging.logger import get_logger

logger = get_logger("api.routes.sandbox")
router = APIRouter(prefix="/sandbox", tags=["sandbox"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class ReplayRequest(BaseModel):
    """Request body for POST /sandbox/replay."""

    cve_id: str
    blueprint_id: str
    attack_script: str | None = None
    dry_run: bool = True  # Safe default — real replay requires explicit opt-in
    actor: str = "sandbox_replay"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/replay",
    summary="Start a sandbox replay",
    response_model=dict[str, Any],
    status_code=status.HTTP_202_ACCEPTED,
)
def start_replay(body: ReplayRequest) -> dict[str, Any]:
    """Triggers a sandbox attack replay for a blueprint.

    Runs the attack in an isolated Docker environment (or dry-run mode for CI).
    Returns the replay session record upon completion.

    **Warning:** Non-dry-run replays require Docker and the sandbox containers.
    Set ``dry_run: true`` for safe testing.
    """
    try:
        # Load blueprint by re-generating (or look it up from the graph)
        tr_agent = ThreatReconstructionAgent()
        try:
            bp = tr_agent.blueprint(cve_id=body.cve_id, actor="threat_reconstruction")
        except CVENotAnalyzedError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        # Override blueprint_id to match requested if different
        if bp.blueprint_id != body.blueprint_id and body.blueprint_id:
            bp.blueprint_id = body.blueprint_id

        replay_agent = SandboxReplayAgent(dry_run=body.dry_run)
        session = replay_agent.replay(
            blueprint=bp,
            attack_script=body.attack_script,
            actor=body.actor,
        )
        return session.model_dump()
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Sandbox replay failed", error=str(exc))
        raise HTTPException(status_code=500, detail=f"Replay error: {exc}") from exc


@router.get(
    "/replay/{session_id}",
    summary="Get replay session",
    response_model=dict[str, Any],
)
def get_replay_session(session_id: str) -> dict[str, Any]:
    """Returns the current state of a sandbox replay session."""
    try:
        db = PostgresClient()
        row = db.fetch_one(
            "SELECT * FROM replay_sessions WHERE session_id = %s",
            (session_id,),
        )
        if not row:
            raise HTTPException(
                status_code=404,
                detail=f"Replay session '{session_id}' not found.",
            )
        return dict(row)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to retrieve replay session", error=str(exc))
        raise HTTPException(status_code=500, detail="Session retrieval error") from exc


@router.get(
    "/replay/{session_id}/telemetry",
    summary="Get telemetry artifact IDs for a session",
    response_model=list[str],
)
def get_session_telemetry(session_id: str) -> list[str]:
    """Returns the list of evidence artifact IDs captured during a replay session."""
    try:
        db = PostgresClient()
        row = db.fetch_one(
            "SELECT artifact_ids FROM replay_sessions WHERE session_id = %s",
            (session_id,),
        )
        if not row:
            raise HTTPException(
                status_code=404, detail=f"Session '{session_id}' not found."
            )
        artifact_ids = row["artifact_ids"]
        if isinstance(artifact_ids, str):
            artifact_ids = json.loads(artifact_ids)
        return list(artifact_ids)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to retrieve telemetry", error=str(exc))
        raise HTTPException(
            status_code=500, detail="Telemetry retrieval error"
        ) from exc


@router.get(
    "/replay/{session_id}/report",
    summary="Get replay report",
    response_model=dict[str, Any],
)
def get_replay_report(session_id: str) -> dict[str, Any]:
    """Returns the full replay report for a completed session."""
    try:
        db = PostgresClient()
        row = db.fetch_one(
            "SELECT replay_report, status FROM replay_sessions WHERE session_id = %s",
            (session_id,),
        )
        if not row:
            raise HTTPException(
                status_code=404, detail=f"Session '{session_id}' not found."
            )
        if row["status"] != "completed":
            return {"session_id": session_id, "status": row["status"], "report": None}
        report = row["replay_report"]
        if isinstance(report, str):
            report = json.loads(report)
        return {"session_id": session_id, "status": row["status"], "report": report}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("Failed to retrieve replay report", error=str(exc))
        raise HTTPException(status_code=500, detail="Report retrieval error") from exc


@router.get(
    "/sessions",
    summary="List sandbox replay sessions",
    response_model=list[dict[str, Any]],
)
def list_sessions(
    cve_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=20, ge=1, le=200),
) -> list[dict[str, Any]]:
    """Returns a list of sandbox replay sessions with optional filters."""
    try:
        db = PostgresClient()
        clauses: list[str] = []
        params: list[Any] = []
        if cve_id:
            clauses.append("cve_id = %s")
            params.append(cve_id.upper())
        if status_filter:
            clauses.append("status = %s")
            params.append(status_filter)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        rows = db.fetch_all(
            f"SELECT session_id, blueprint_id, cve_id, status, created_at, completed_at "  # noqa: S608
            f"FROM replay_sessions {where} ORDER BY created_at DESC LIMIT %s",
            tuple(params),
        )
        return [dict(r) for r in rows]
    except Exception as exc:
        logger.error("Failed to list sessions", error=str(exc))
        raise HTTPException(status_code=500, detail="Session list error") from exc
