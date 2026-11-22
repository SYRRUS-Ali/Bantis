"""Deliver critical incidents through the dashboard's encrypted Telegram setup."""

from __future__ import annotations

import json
import logging
import os
import re
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from app.incident_models import CriticalAlertORM, IncidentORM
from app.telegram_notifier import send_message

logger = logging.getLogger("detection_engine.telegram")
_TOKEN = re.compile(r"^[0-9]+:[A-Za-z0-9_-]{20,}$")


def _private_bytes(path: Path, *, max_bytes: int = 16384) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > max_bytes):
            raise ValueError("Private operator-owned file required")
        payload = source.read(max_bytes + 1)
    if len(payload) > max_bytes:
        raise ValueError("Private config exceeds size limit")
    return payload


def _private_json(path: Path, *, max_bytes: int = 16384) -> dict:
    payload = _private_bytes(path, max_bytes=max_bytes)
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("Private config must be an object")
    return value


def _private_directory(path: Path) -> None:
    info = path.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o077):
        raise ValueError("Private operator-owned directory required")


def load_telegram_credentials() -> tuple[str, str] | None:
    """Decrypt only the existing Telegram and permission documents; never use env secrets."""
    root = Path(os.environ.get("BANTIS_ORCHESTRATION_STATE", "/run/bantis"))
    key_path = Path(os.environ.get("BANTIS_SECRETS_KEY_FILE", "/run/bantis-key/.secrets.key"))
    try:
        _private_directory(root)
        _private_directory(key_path.parent)
        key_bytes = _private_bytes(key_path, max_bytes=128)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, json.JSONDecodeError):
        logger.warning("Telegram configuration unavailable; critical alert remains queued")
        return None

    try:
        if not key_bytes or len(key_bytes) > 128:
            raise ValueError("Invalid key file")
        cipher = Fernet(key_bytes)
        telegram_envelope = _private_json(root / "telegram.json")
        permissions_envelope = _private_json(root / "permissions.json")
        telegram = _decrypt(cipher, telegram_envelope, "telegram")
        permissions = _decrypt(cipher, permissions_envelope, "permissions")
        if (telegram.get("version") != 1 or telegram.get("enabled") is not True
                or permissions.get("version") != 1 or permissions.get("telegram_messages") is not True):
            return None
        token, chat_id = telegram.get("bot_token"), telegram.get("chat_id")
        if (not isinstance(token, str) or not _TOKEN.fullmatch(token)
                or not isinstance(chat_id, str) or not chat_id or len(chat_id) > 64):
            raise ValueError("Invalid saved Telegram configuration")
        return token, chat_id
    except FileNotFoundError:
        return None
    except (OSError, ValueError, InvalidToken, UnicodeError, json.JSONDecodeError):
        logger.warning("Telegram configuration unavailable; critical alert remains queued")
        return None


def _decrypt(cipher: Fernet, envelope: dict, purpose: str) -> dict:
    if (set(envelope) != {"version", "ciphertext"} or envelope.get("version") != 2
            or not isinstance(envelope.get("ciphertext"), str)):
        raise ValueError("Invalid encrypted document")
    payload = json.loads(cipher.decrypt(envelope["ciphertext"].encode("ascii")))
    if (not isinstance(payload, dict) or payload.get("purpose") != purpose
            or not isinstance(payload.get("data"), dict)):
        raise ValueError("Encrypted document purpose mismatch")
    return payload["data"]


def _message(incident: IncidentORM) -> str:
    summary = " ".join((incident.summary or "").split())[:2500]
    techniques = ", ".join((incident.mitre_techniques or [])[:20])[:500]
    return ("Bantis critical security incident\n"
            f"Incident: {incident.incident_id}\n"
            f"Pattern: {incident.pattern}\n"
            f"Severity: {incident.severity}\n"
            f"Confidence: {incident.confidence:.2f}\n"
            f"Summary: {summary}\n"
            f"MITRE techniques: {techniques or 'N/A'}")[:3900]


def deliver_pending_critical_alerts(session: Session) -> int:
    """Attempt pending outbox rows once; false or uncertain sends are retried next pass."""
    credentials = load_telegram_credentials()
    if credentials is None:
        return 0
    token, chat_id = credentials
    delivered = 0
    now = datetime.now(timezone.utc)
    rows = session.scalars(
        select(CriticalAlertORM).where(
            CriticalAlertORM.delivered_at.is_(None),
            or_(CriticalAlertORM.claimed_until.is_(None), CriticalAlertORM.claimed_until <= now),
        )
        .order_by(CriticalAlertORM.created_at).limit(20)
    ).all()
    for row in rows:
        # Atomic short lease ensures overlapping scheduler processes don't send
        # the same outbox item at once. An interrupted process releases itself
        # after the bounded send timeout plus this lease.
        claim_now = datetime.now(timezone.utc)
        claim_until = claim_now + timedelta(seconds=30)
        claim = session.execute(
            update(CriticalAlertORM)
            .where(
                CriticalAlertORM.incident_id == row.incident_id,
                CriticalAlertORM.delivered_at.is_(None),
                or_(CriticalAlertORM.claimed_until.is_(None), CriticalAlertORM.claimed_until <= claim_now),
            )
            .values(attempts=CriticalAlertORM.attempts + 1, claimed_until=claim_until)
        )
        if claim.rowcount != 1:
            session.rollback()
            continue
        session.commit()
        incident = session.get(IncidentORM, row.incident_id)
        row = session.get(CriticalAlertORM, row.incident_id)
        if incident is None or incident.severity != "critical":
            row.delivered_at = datetime.now(timezone.utc)
            row.claimed_until = None
            session.commit()
            continue
        try:
            sent = send_message(_message(incident), bot_token=token, chat_id=chat_id)
        except Exception:
            sent = False
            logger.exception("Telegram delivery failed for critical incident %s", incident.incident_id)
        if sent:
            row.delivered_at = datetime.now(timezone.utc)
            row.claimed_until = None
            delivered += 1
        else:
            row.claimed_until = None
            logger.warning("Telegram delivery failed for critical incident %s; it will be retried", incident.incident_id)
        session.commit()
    return delivered