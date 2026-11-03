"""FastAPI application: `uvicorn app.main:app`."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .api.routes import router
from .config import get_settings
from .services import bootstrap
from .store import Store, build_store

log = logging.getLogger("kc-upgrade-analyzer")


def create_app(store: Store | None = None, settings=None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        s = app.state.store
        for attempt in range(30):  # wait for Elasticsearch in docker compose
            if s.ping():
                break
            log.warning("store not reachable yet (attempt %s)", attempt + 1)
            time.sleep(2)
        s.ensure_indices()
        if settings.auto_bootstrap:
            log.info("AUTO_BOOTSTRAP: %s", bootstrap(s, settings).get("assessments"))
        yield

    app = FastAPI(title="Keycloak Breaking Change Impact Analyzer", version="0.1.0", lifespan=lifespan)
    app.state.store = store or build_store(settings)
    app.state.settings = settings
    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
    app.include_router(router, prefix="/api")
    return app


app = create_app()
