import asyncio
import hmac
import secrets
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import anyio
import httpx
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .audit import AuditPage, AuditReader
from .config import Settings
from .copilot import CopilotClient, Question
from .detection import DetectionClient, Incident, IncidentPage, Severity, UpstreamError
from .live_feed import LiveFeed

STATIC = Path(__file__).parent / "static"
COOKIE = "bantis_dashboard_session"


class Login(BaseModel):
    token: str = Field(min_length=1, max_length=512, repr=False)


class Sessions:
    def __init__(self, duration: int):
        self.duration = duration
        self.entries: dict[str, float] = {}

    def valid(self, session_id: str | None) -> bool:
        return self.entries.get(session_id, 0) > time.monotonic()

    def issue(self) -> str:
        now = time.monotonic()
        self.entries = {
            key: expiry for key, expiry in self.entries.items() if expiry > now
        }
        if len(self.entries) >= 128:
            raise HTTPException(429, "Session limit reached; sign out unused sessions")
        session_id = secrets.token_urlsafe(32)
        self.entries[session_id] = now + self.duration
        return session_id


class StatusFeed:
    def __init__(self, detection: DetectionClient, interval: float):
        self.detection = detection
        self.interval = interval
        self.changed = asyncio.Condition()
        self.snapshot = {
            "type": "dashboard.snapshot",
            "sequence": 0,
            "observed_at": None,
            "last_success_at": None,
            "detection_engine": {"status": "connecting", "total_incidents": None},
        }

    async def poll(self):
        now = datetime.now(timezone.utc).isoformat()
        previous = self.snapshot
        try:
            page = await self.detection.incidents({"limit": 1, "offset": 0})
            engine = {"status": "available", "total_incidents": page.total}
            success = now
        except UpstreamError:
            engine = {
                "status": "unavailable",
                "total_incidents": previous["detection_engine"]["total_incidents"],
            }
            success = previous["last_success_at"]
        async with self.changed:
            self.snapshot = {
                "type": "dashboard.snapshot",
                "sequence": previous["sequence"] + 1,
                "observed_at": now,
                "last_success_at": success,
                "detection_engine": engine,
            }
            self.changed.notify_all()

    async def run(self):
        while True:
            await self.poll()
            await asyncio.sleep(self.interval)


def create_app(
    settings: Settings | None = None, *, transport=None, copilot_transport=None
) -> FastAPI:
    settings = settings or Settings.from_env()
    sessions = Sessions(settings.session_seconds)
    audit_reader = AuditReader(settings.audit_path)

    @asynccontextmanager
    async def lifespan(app):
        async with (
            httpx.AsyncClient(
                base_url=settings.detection_url + "/",
                timeout=3.0,
                follow_redirects=False,
                trust_env=False,
                transport=transport,
            ) as client,
            httpx.AsyncClient(
                base_url=settings.copilot_url + "/",
                headers={"Authorization": f"Bearer {settings.copilot_token}"}
                if settings.copilot_token
                else {},
                follow_redirects=False,
                trust_env=False,
                transport=copilot_transport,
            ) as copilot_client,
        ):
            app.state.copilot = CopilotClient(
                copilot_client, bool(settings.copilot_token)
            )
            app.state.detection = DetectionClient(client)
            app.state.feed = StatusFeed(app.state.detection, settings.poll_seconds)
            app.state.live_feed = LiveFeed(app.state.detection, settings.poll_seconds)
            tasks = [
                asyncio.create_task(feed.run())
                for feed in (app.state.feed, app.state.live_feed)
            ]
            try:
                yield
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                sessions.entries.clear()

    app = FastAPI(
        title="Bantis Dashboard",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.sessions = sessions
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=[urlsplit(settings.origin).hostname]
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; object-src 'none'; "
            "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
        )
        return response

    def same_origin(request: Request):
        origin = request.headers.get("origin")
        if origin is not None and origin != settings.origin:
            raise HTTPException(403, "Cross-origin request rejected")

    def authenticated(request: Request):
        if not sessions.valid(request.cookies.get(COOKIE)):
            raise HTTPException(401, "Sign in to access the dashboard")

    @app.exception_handler(UpstreamError)
    async def upstream_error(request, exc):
        return JSONResponse(status_code=exc.status, content={"detail": exc.message})

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Validation errors must never echo the login token or arbitrary request input.
        return JSONResponse(
            status_code=422, content={"detail": "Invalid request parameters"}
        )

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "dashboard"}

    @app.post("/api/session", dependencies=[Depends(same_origin)])
    async def login(body: Login, request: Request, response: Response):
        if not hmac.compare_digest(body.token.encode(), settings.token.encode()):
            raise HTTPException(401, "Invalid dashboard access token")
        existing = request.cookies.get(COOKIE)
        session_id = sessions.issue()
        sessions.entries.pop(existing, None)
        response.set_cookie(
            COOKIE,
            session_id,
            httponly=True,
            samesite="strict",
            secure=settings.origin.startswith("https://"),
            max_age=settings.session_seconds,
        )
        return {"authenticated": True}

    @app.get("/api/session", dependencies=[Depends(authenticated)])
    async def session():
        return {"authenticated": True}

    @app.delete("/api/session", dependencies=[Depends(same_origin)])
    async def logout(request: Request, response: Response):
        sessions.entries.pop(request.cookies.get(COOKIE), None)
        response.delete_cookie(COOKIE)
        return {"authenticated": False}

    @app.get("/api/status", dependencies=[Depends(authenticated)])
    async def status(request: Request):
        return request.app.state.feed.snapshot

    @app.get("/api/live-feed", dependencies=[Depends(authenticated)])
    async def live_feed(request: Request):
        return request.app.state.live_feed.snapshot

    @app.get(
        "/api/audit-log",
        response_model=AuditPage,
        dependencies=[Depends(authenticated)],
    )
    def audit_log(
        actor: str | None = Query(default=None, max_length=512),
        action_id: str | None = Query(default=None, max_length=512),
        incident_id: str | None = Query(default=None, max_length=512),
        event: str | None = Query(default=None, max_length=200),
        status: str | None = Query(default=None, max_length=200),
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = Query(default=20, ge=1, le=100),
        offset: int = Query(default=0, ge=0, le=100000),
        through_sequence: int | None = Query(default=None, ge=0),
    ):
        if since is not None:
            since = Incident.utc_time(since)
        if until is not None:
            until = Incident.utc_time(until)
        if since and until and since > until:
            raise HTTPException(422, "Start time must be before end time")
        return audit_reader.page(
            limit=limit,
            offset=offset,
            through_sequence=through_sequence,
            since=since,
            until=until,
            actor=actor,
            action_id=action_id,
            incident_id=incident_id,
            event=event,
            status=status,
        )

    @app.get(
        "/api/incidents",
        response_model=IncidentPage,
        dependencies=[Depends(authenticated)],
    )
    async def incidents(
        request: Request,
        severity: Severity | None = None,
        pattern: str | None = Query(default=None, max_length=200),
        since: datetime | None = None,
        limit: int = Query(default=20, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ):
        params = {"limit": limit, "offset": offset}
        if severity is not None:
            params["severity"] = severity
        if pattern is not None:
            params["pattern"] = pattern
        if since is not None:
            params["since"] = since.isoformat()
        return await request.app.state.detection.incidents(params)

    @app.get(
        "/api/incidents/{incident_id}",
        response_model=Incident,
        dependencies=[Depends(authenticated)],
    )
    async def incident(request: Request, incident_id: str):
        return await request.app.state.detection.incident(incident_id)

    @app.get(
        "/api/incidents/{incident_id}/events", dependencies=[Depends(authenticated)]
    )
    async def evidence(request: Request, incident_id: str):
        return await request.app.state.detection.evidence(incident_id)

    @app.get(
        "/api/incidents/{incident_id}/analysis", dependencies=[Depends(authenticated)]
    )
    async def analysis(request: Request, incident_id: str):
        await request.app.state.detection.incident(incident_id)
        return await request.app.state.copilot.request(incident_id, "analysis")

    @app.get(
        "/api/incidents/{incident_id}/questions", dependencies=[Depends(authenticated)]
    )
    async def questions(request: Request, incident_id: str):
        await request.app.state.detection.incident(incident_id)
        return await request.app.state.copilot.request(incident_id, "questions")

    @app.post(
        "/api/incidents/{incident_id}/questions",
        status_code=201,
        dependencies=[Depends(authenticated), Depends(same_origin)],
    )
    async def ask(request: Request, incident_id: str, body: Question):
        await request.app.state.detection.incident(incident_id)
        return await request.app.state.copilot.request(incident_id, "questions", body)

    @app.websocket("/ws")
    @app.websocket("/ws/events")
    async def websocket(websocket: WebSocket):
        session_id = websocket.cookies.get(COOKIE)
        if websocket.headers.get("origin") != settings.origin or not sessions.valid(
            session_id
        ):
            await websocket.close(code=1008)
            return
        await websocket.accept()
        feed = (
            websocket.app.state.live_feed
            if websocket.url.path == "/ws/events"
            else websocket.app.state.feed
        )

        async def send_updates():
            sequence = -1
            while True:
                if not sessions.valid(session_id):
                    await websocket.close(code=1008)
                    return
                async with feed.changed:
                    await feed.changed.wait_for(
                        lambda previous=sequence: feed.snapshot["sequence"] != previous
                    )
                    snapshot = feed.snapshot
                    sequence = snapshot["sequence"]
                if not sessions.valid(session_id):
                    await websocket.close(code=1008)
                    return
                await asyncio.wait_for(websocket.send_json(snapshot), timeout=5)

        async def receive_disconnect():
            while True:
                message = await websocket.receive()
                if message["type"] == "websocket.disconnect":
                    return

        # Keep both stream tasks inside the connection's cancellation scope.
        # Raw asyncio tasks plus an unshielded gather can leak CancelledError
        # when ASGI shutdown races with disconnect cleanup.
        async with anyio.create_task_group() as tasks:

            async def run_stream(operation):
                try:
                    await operation()
                except (WebSocketDisconnect, TimeoutError, RuntimeError):
                    pass
                finally:
                    tasks.cancel_scope.cancel()

            tasks.start_soon(run_stream, send_updates)
            tasks.start_soon(run_stream, receive_disconnect)

    @app.get("/", include_in_schema=False)
    @app.get("/live-feed", include_in_schema=False)
    @app.get("/incidents", include_in_schema=False)
    @app.get("/audit-log", include_in_schema=False)
    async def index():
        return FileResponse(STATIC / "index.html")

    app.mount("/static", StaticFiles(directory=STATIC), name="static")
    return app