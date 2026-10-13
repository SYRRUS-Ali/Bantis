from __future__ import annotations

import argparse
import hmac
import ipaddress
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from decision_log import DEFAULT_PATH as DEFAULT_DECISION_LOG_PATH
from decision_log import DecisionLog, FollowupRecord
from providers.base import AIProvider

logger = logging.getLogger("ai_copilot.api")

QUESTION_MAX_CHARS = 2000
HISTORY_TURNS = 5
DEFAULT_MAX_QUESTIONS_PER_HOUR = 60
MIN_TOKEN_LENGTH = 16
_RATE_WINDOW = timedelta(hours=1)

_CREDENTIAL_PATTERNS = {
    "an AWS access key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "a private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "a GitHub token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "an Anthropic API key": re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
}


class QuestionIn(BaseModel):
    question: str = Field(min_length=1, max_length=QUESTION_MAX_CHARS)

    @field_validator("question")
    @classmethod
    def _real_question_without_credentials(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("question must not be empty")
        for label, pattern in _CREDENTIAL_PATTERNS.items():
            if pattern.search(value):
                raise ValueError(
                    f"question appears to contain {label}; credentials are never sent to the AI provider -- "
                    "describe it instead of pasting it"
                )
        return value


class FollowupOut(BaseModel):
    followup_id: str
    incident_id: str
    asked_at: datetime
    question: str
    answer: str
    model: str


def _out(record: FollowupRecord) -> FollowupOut:
    return FollowupOut(
        followup_id=record.followup_id,
        incident_id=record.incident_id,
        asked_at=record.asked_at,
        question=record.question,
        answer=record.answer or "",
        model=record.model,
    )


def create_app(
    decision_log: DecisionLog,
    provider: AIProvider,
    api_token: str,
    max_questions_per_hour: int | None = DEFAULT_MAX_QUESTIONS_PER_HOUR,
) -> FastAPI:
    if not api_token or len(api_token) < MIN_TOKEN_LENGTH:
        raise ValueError(f"the API token must be at least {MIN_TOKEN_LENGTH} characters")
    expected_header = f"Bearer {api_token}".encode()

    def require_token(authorization: str | None = Header(default=None)) -> None:
        # compare_digest: a plain == leaks, through timing, how much of a
        # guessed token was right.
        if authorization is None or not hmac.compare_digest(authorization.encode(), expected_header):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="missing or invalid bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    def analyzed_decision(incident_id: str):
        decisions = decision_log.for_incident(incident_id)
        if not decisions:
            raise HTTPException(status_code=404, detail=f"no decision recorded for incident {incident_id!r}")
        return decisions[0].record

    app = FastAPI(title="Bantis AI Copilot", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post(
        "/incidents/{incident_id}/questions",
        status_code=status.HTTP_201_CREATED,
        response_model=FollowupOut,
        dependencies=[Depends(require_token)],
    )
    def ask(incident_id: str, body: QuestionIn) -> FollowupOut:
        record = analyzed_decision(incident_id)
        if record.request is None or record.response is None:
            # A skipped incident, or one whose evidence was incomplete: there
            # is no recorded request to ground an answer in, and fetching raw
            # events here would bypass the converter's allowlist.
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"incident {incident_id!r} has no analysis to ask about (outcome: {record.outcome})",
            )

        if max_questions_per_hour is not None:
            asked = decision_log.count_followups_since(datetime.now(timezone.utc) - _RATE_WINDOW)
            if asked >= max_questions_per_hour:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"limit of {max_questions_per_hour} questions per hour reached",
                    headers={"Retry-After": "60"},
                )

        history = [(f.question, f.answer) for f in decision_log.followups_for(incident_id) if f.answer]
        trace = provider.ask(record.request, record.response, history[-HISTORY_TURNS:], body.question)

        followup = FollowupRecord(
            incident_id=incident_id,
            question=body.question,
            answer=trace.answer,
            error=trace.error,
            model=getattr(provider, "model", type(provider).__name__),
            system_prompt=trace.system_prompt,
            attempts=trace.attempts,
        )
        decision_log.append_followup(followup)  # recorded whether it succeeded or not

        if trace.answer is None:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"the AI provider could not answer: {trace.error}",
            )
        return _out(followup)

    @app.get(
        "/incidents/{incident_id}/questions",
        response_model=list[FollowupOut],
        dependencies=[Depends(require_token)],
    )
    def list_questions(incident_id: str) -> list[FollowupOut]:
        analyzed_decision(incident_id)
        return [_out(f) for f in decision_log.followups_for(incident_id) if f.answer is not None]

    return app


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the AI Copilot's follow-up question API.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8100)
    parser.add_argument("--decision-log", default=DEFAULT_DECISION_LOG_PATH)
    parser.add_argument("--max-questions-per-hour", type=int, default=DEFAULT_MAX_QUESTIONS_PER_HOUR)
    parser.add_argument("--no-rate-limit", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s")

    token = os.environ.get("COPILOT_API_TOKEN", "")
    if len(token) < MIN_TOKEN_LENGTH:
        print(
            f"COPILOT_API_TOKEN must be set to at least {MIN_TOKEN_LENGTH} characters, e.g.\n"
            "  export COPILOT_API_TOKEN=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')",
            file=sys.stderr,
        )
        return 2
    if not _is_loopback(args.host):
        logger.warning("listening on %s over plain HTTP: the bearer token travels in cleartext -- put TLS in front", args.host)

    import uvicorn

    from providers.claude import ClaudeProvider

    app = create_app(
        DecisionLog(args.decision_log),
        ClaudeProvider(),
        token,
        max_questions_per_hour=None if args.no_rate_limit else args.max_questions_per_hour,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())