import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import init_db
from app.routers import events, incidents
from app.scheduler import CorrelationScheduler, interval_from_env


def _configure_logging() -> None:
    # uvicorn configures only its own loggers; without this, the scheduler's
    # INFO lines (incidents formed, the interval in use) were dropped.
    logger = logging.getLogger("detection_engine")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    _configure_logging()
    init_db()
    interval = interval_from_env()
    scheduler = CorrelationScheduler(interval) if interval > 0 else None
    if scheduler is not None:
        scheduler.start()
    try:
        yield
    finally:
        if scheduler is not None:
            scheduler.stop()


app = FastAPI(title="Bantis Detection Engine", version="0.1.0", lifespan=lifespan)

app.include_router(events.router)
app.include_router(incidents.router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}