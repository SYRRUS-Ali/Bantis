import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.cache import redis_client
from app.db import init_db
from app.logging_config import configure_logging
from app.middleware import AccessLogMiddleware
from app.routers import auth, tasks

# `or "INFO"` guards against the same empty-string-env-var gotcha documented
# elsewhere in this project (see .env.example) — configure this before
# anything else runs, so startup logs are JSON too.
configure_logging(level=os.environ.get("LOG_LEVEL") or "INFO")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await redis_client.aclose()


app = FastAPI(title="compose-multiservice-app", version="0.1.0", lifespan=lifespan)

app.add_middleware(AccessLogMiddleware)

app.include_router(auth.router)
app.include_router(tasks.router)


@app.get("/")
def root() -> dict[str, str]:
    """Basic landing endpoint to confirm the service is reachable."""
    return {"message": "compose-multiservice-app API is running"}


@app.get("/health")
def health_check() -> dict[str, str]:
    """Liveness check used by Docker Compose / orchestration healthchecks."""
    return {"status": "ok"}
