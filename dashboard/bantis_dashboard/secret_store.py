"""Authenticated local configuration encryption with private, durable key storage."""

import hashlib
import hmac
import json
import os
import stat
import tempfile
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .admin import AdminError

KEY_NAME = ".secrets.key"
NAMES = {"ai-provider", "telegram", "permissions"}


def private_read(path: Path, limit: int = 16384) -> bytes:
    # O_NONBLOCK prevents an untrusted FIFO from hanging configuration reads.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > limit):
            raise ValueError("Private regular configuration file required")
        content = source.read(limit + 1)
        if len(content) > limit:
            raise ValueError("Configuration exceeds size limit")
        return content


def private_directory(path: Path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("Private operator-owned directory required")


class SecretStore:
    def __init__(self, directory: Path, key_file: Path | None = None):
        self.directory = directory
        self.key_file = key_file if key_file is not None else directory / KEY_NAME
        try:
            if not directory.is_absolute() or not self.key_file.is_absolute():
                raise ValueError("Absolute storage paths required")
            private_directory(directory)
            private_directory(self.key_file.parent)
            if key_file is None and not self.key_file.exists():
                # Never replace a lost key while any encrypted document remains.
                for name in NAMES:
                    path = directory / f"{name}.json"
                    try:
                        data = json.loads(private_read(path))
                    except FileNotFoundError:
                        continue
                    if not isinstance(data, dict) or data.get("version") != 1:
                        raise ValueError("Existing encrypted or invalid configuration requires its original key")
                self._create_key()
            self._cipher()
            for name in NAMES:
                try:
                    self.read(name, allow_legacy=True)
                except FileNotFoundError:
                    pass
        except (OSError, ValueError) as exc:
            raise AdminError(503, "Encrypted storage is unavailable. Restore the original private key and check directory permissions") from exc

    def _create_key(self):
        # Publish a fully written key atomically, without replacing another process's key.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=self.key_file.parent, delete=False) as target:
                temporary = target.name
                os.fchmod(target.fileno(), 0o600)
                target.write(Fernet.generate_key())
                target.flush()
                os.fsync(target.fileno())
            try:
                os.link(temporary, self.key_file)
                self._sync_directory(self.key_file.parent)
            except FileExistsError:
                pass
        finally:
            if temporary is not None:
                os.unlink(temporary)

    def _cipher(self):
        private_directory(self.directory)
        private_directory(self.key_file.parent)
        key = private_read(self.key_file, 128)
        digest = hashlib.sha256(key).digest()
        if hasattr(self, "_key_digest") and not hmac.compare_digest(self._key_digest, digest):
            raise ValueError("The original encryption key was replaced")
        cipher = Fernet(key)
        self._key_digest = digest
        return cipher

    @staticmethod
    def _sync_directory(directory):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def read(self, name: str, *, allow_legacy=False):
        if name not in NAMES:
            raise ValueError("Unknown configuration document")
        try:
            cipher = self._cipher()
            data = json.loads(private_read(self.directory / f"{name}.json"))
            if allow_legacy and isinstance(data, dict) and data.get("version") == 1:
                return data, True
            if (not isinstance(data, dict) or set(data) != {"version", "ciphertext"}
                    or type(data["version"]) is not int or data["version"] != 2
                    or not isinstance(data["ciphertext"], str)):
                raise ValueError("Encrypted configuration required")
            payload = json.loads(cipher.decrypt(data["ciphertext"].encode("ascii")))
            if (not isinstance(payload, dict) or set(payload) != {"purpose", "data"}
                    or payload["purpose"] != name or not isinstance(payload["data"], dict)):
                raise ValueError("Configuration purpose mismatch")
            return payload["data"], False
        except FileNotFoundError as exc:
            # A missing configuration is distinct from a missing encryption key.
            if not self.key_file.exists():
                raise AdminError(503, "The encryption key is unavailable. Restore the original key") from exc
            raise
        except (OSError, ValueError, InvalidToken) as exc:
            raise AdminError(503, "Encrypted configuration is unavailable or invalid. Check the original key and private permissions") from exc

    def write(self, name: str, data: dict):
        if name not in NAMES:
            raise ValueError("Unknown configuration document")
        temporary = None
        try:
            cipher = self._cipher()
            payload = json.dumps({"purpose": name, "data": data}).encode()
            envelope = {"version": 2, "ciphertext": cipher.encrypt(payload).decode("ascii")}
            with tempfile.NamedTemporaryFile(mode="w", dir=self.directory, delete=False) as target:
                temporary = target.name
                os.fchmod(target.fileno(), 0o600)
                json.dump(envelope, target)
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.directory / f"{name}.json")
            self._sync_directory(self.directory)
        except (OSError, ValueError) as exc:
            raise AdminError(503, "Encrypted configuration could not be saved. Check private storage and the original key") from exc
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)

    def status(self):
        try:
            self._cipher()
        except (OSError, ValueError) as exc:
            raise AdminError(503, "Encrypted storage is unavailable. Restore the original private key") from exc
        for name in NAMES:
            try:
                self.read(name)
            except FileNotFoundError:
                pass
        return {"encryption": "Fernet", "key_available": True, "private_permissions": True}