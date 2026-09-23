"""Developer graph viewer route — serves the static HTML viewer page."""

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse

from api.dependencies import get_app_settings
from api.routes.graph import _get_client_ip, _guard_dev_endpoint
from core.config.settings import Settings
from core.logging.logger import get_logger

router = APIRouter(prefix="/dev", tags=["Developer Tools"])
logger = get_logger(__name__)

_VIEWER_PATH = Path(__file__).parent.parent / "static" / "dev_viewer.html"


@router.get(
    "/viewer",
    response_class=HTMLResponse,
    summary="Developer graph viewer (localhost only)",
    include_in_schema=True,
)
def dev_viewer(
    request: Request,
    settings: Settings = Depends(get_app_settings),
) -> HTMLResponse:
    """Serves the developer graph visualization HTML page.

    .. warning::
        This is a **developer-only tool** with no authentication.
        It must not be exposed publicly.
        Restricted to localhost by default (``DEV_VIEWER_ALLOW_REMOTE=false``).

    Returns:
        The ``dev_viewer.html`` file as an HTML response.
    """
    client_ip = _get_client_ip(request)
    logger.info(
        "Developer viewer accessed",
        client_ip=client_ip,
        path=request.url.path,
    )

    _guard_dev_endpoint(request, settings)

    if not _VIEWER_PATH.exists():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Developer viewer HTML file not found.",
        )

    return HTMLResponse(content=_VIEWER_PATH.read_text(encoding="utf-8"))
