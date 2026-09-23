from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db import init_db
from app.routers import events


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(title="Bantis Detection Engine", version="0.1.0", lifespan=lifespan)

app.include_router(events.router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}