import hashlib
import hmac
import os
import secrets
import sqlite3
import stat
import threading
import time
from collections import deque
from contextlib import closing, contextmanager
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AdminError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status, self.message = status, message


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
    password: str = Field(min_length=1, max_length=128, repr=False)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value):
        return value.lower()


class NewAdmin(Credentials):
    bootstrap_token: str = Field(min_length=1, max_length=512, repr=False)
    password: str = Field(min_length=15, max_length=128, repr=False)
    password_confirmation: str = Field(min_length=15, max_length=128, repr=False)

    @model_validator(mode="after")
    def matching_passwords(self):
        if not self.password.strip() or self.password != self.password_confirmation:
            raise ValueError("Passwords must match and must not be blank")
        return self


class AuthLimiter:
    """Bound work across clients in this single-worker local service."""

    def __init__(self):
        self.attempts = deque()
        self.lock = threading.Lock()

    def check(self):
        with self.lock:
            now = time.monotonic()
            while self.attempts and self.attempts[0] <= now - 60:
                self.attempts.popleft()
            if len(self.attempts) >= 10:
                raise AdminError(429, "Too many authentication attempts. Try again in one minute")
            self.attempts.append(now)


def password_hash(password: str, salt: bytes) -> bytes:
    # OWASP scrypt baseline; fixed, versioned parameters cannot come from requests.
    try:
        return hashlib.scrypt(password.encode(), salt=salt, n=2**17, r=8, p=1,
                              maxmem=256 * 1024 * 1024, dklen=32)
    except (ValueError, MemoryError) as exc:
        raise AdminError(503, "Password authentication is unavailable") from exc


class AdminStore:
    def __init__(self, directory: Path):
        self.path = directory / "admin.sqlite3"
        self.work = threading.BoundedSemaphore(1)
        try:
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            info = directory.stat()
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise OSError("Administrator state directory must be private")
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                new_database = True
            except FileExistsError:
                fd = os.open(self.path, os.O_RDWR | os.O_NOFOLLOW)
                new_database = False
            with os.fdopen(fd, "rb") as source:
                info = os.fstat(source.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise OSError("Administrator database must be private")
            with self.connection() as db:
                if new_database:
                    db.execute("""CREATE TABLE administrator (
                        singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                        username TEXT NOT NULL, salt BLOB NOT NULL,
                        password_hash BLOB NOT NULL, algorithm TEXT NOT NULL
                    )""")
                self._record(db)
        except (OSError, sqlite3.Error) as exc:
            raise AdminError(503, "Administrator state is unavailable; check its path and private permissions") from exc

    @contextmanager
    def connection(self):
        try:
            # Never recreate a missing database during a running service.
            with closing(sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=1)) as db:
                db.row_factory = sqlite3.Row
                yield db
        except (OSError, sqlite3.Error) as exc:
            raise AdminError(503, "Administrator state is unavailable") from exc

    @staticmethod
    def _record(db):
        rows = db.execute("SELECT singleton, username, salt, password_hash, algorithm FROM administrator").fetchall()
        if not rows:
            return None
        row = rows[0]
        if (len(rows) != 1 or row["singleton"] != 1 or row["algorithm"] != "scrypt-v1"
                or not isinstance(row["salt"], bytes) or len(row["salt"]) != 16
                or not isinstance(row["password_hash"], bytes) or len(row["password_hash"]) != 32
                or not isinstance(row["username"], str) or not row["username"]):
            raise AdminError(503, "Administrator state is invalid")
        return row

    def created(self) -> bool:
        with self.connection() as db:
            return self._record(db) is not None

    @contextmanager
    def password_work(self):
        if not self.work.acquire(blocking=False):
            raise AdminError(429, "Authentication is busy. Try again shortly")
        try:
            yield
        finally:
            self.work.release()

    def create(self, username: str, password: str):
        with self.password_work(), self.connection() as db:
            # The singleton constraint and write transaction cover other processes too.
            with db:
                db.execute("BEGIN IMMEDIATE")
                if self._record(db) is not None:
                    raise AdminError(409, "Administrator already exists. Sign in to continue")
                salt = secrets.token_bytes(16)
                digest = password_hash(password, salt)
                db.execute("INSERT INTO administrator VALUES (1, ?, ?, ?, 'scrypt-v1')",
                           (username, salt, digest))

    def authenticate(self, username: str, password: str) -> bool:
        with self.password_work(), self.connection() as db:
            row = self._record(db)
            # Use the same password work even for an absent account or wrong username.
            salt = row["salt"] if row else b"\0" * 16
            digest = password_hash(password, salt)
            expected = row["password_hash"] if row else b"\0" * 32
            matches = hmac.compare_digest(digest, expected)
            return bool(row and matches and hmac.compare_digest(username.encode(), row["username"].encode()))