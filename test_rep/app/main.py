"""FastAPI application entrypoint.

Минимальный FastAPI-app, подключающий роуты из `app.views` и шаблоны
Jinja2. Используется как demo-репо для live e2e SunSecurityBot.
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.templating import Jinja2Templates

from app import views
from config.settings import get_settings

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def create_app() -> FastAPI:
    """Сборка FastAPI-приложения."""
    settings = get_settings()
    app = FastAPI(
        title="SunSec demo app",
        version="0.1.0",
        debug=settings.debug,
    )

    # share templates через app.state — handlers достают по запросу
    app.state.templates = TEMPLATES

    app.include_router(views.router)

    @app.get("/health")
    def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "service": "sunsec-demo"})

    return app


app = create_app()
