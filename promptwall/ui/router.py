"""Serving the console pages.

Files on disk rather than strings in Python: an operator who wants to change
a label, and a reviewer who wants to see what changed, should both be looking
at HTML.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, Response

STATIC = Path(__file__).parent / "static"

router = APIRouter(tags=["ui"])

#: Pages the console serves, and the file each one renders.
PAGES = {
    "dashboard": "dashboard.html",
    "playground": "playground.html",
}


@lru_cache(maxsize=len(PAGES))
def _page(name: str) -> str:
    return (STATIC / PAGES[name]).read_text(encoding="utf-8")


@lru_cache(maxsize=4)
def _asset(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def _render(request: Request, name: str) -> Response:
    if not request.app.state.settings.ui.enabled:
        return PlainTextResponse("the console is disabled (PW_UI_ENABLED)\n", status_code=404)
    return HTMLResponse(_page(name))


@router.get("/dashboard", include_in_schema=False)
async def dashboard(request: Request) -> Response:
    return _render(request, "dashboard")


@router.get("/playground", include_in_schema=False)
async def playground(request: Request) -> Response:
    return _render(request, "playground")


@router.get("/ui/console.css", include_in_schema=False)
async def stylesheet(request: Request) -> Response:
    """The one shared asset. Served from here rather than mounted as a static
    directory so the console cannot become a way to read arbitrary files out
    of the package."""
    if not request.app.state.settings.ui.enabled:
        return PlainTextResponse("", status_code=404)
    return Response(_asset("console.css"), media_type="text/css")
