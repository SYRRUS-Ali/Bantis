"""Administrator-controlled dashboard capabilities; controller policy stays separate."""

import threading

from pydantic import BaseModel, ConfigDict

from .admin import AdminError


class PermissionsSave(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    ai_requests: bool
    telegram_messages: bool
    response_decisions: bool


class PermissionsSetup:
    def __init__(self, store, *, response_enabled=False):
        self.store = store
        self.response_enabled = response_enabled
        self.lock = threading.RLock()
        self.generation = 0

    def status(self):
        with self.lock:
            try:
                data, _ = self.store.read("permissions")
            except FileNotFoundError:
                data = None
            if data is None:
                selected = PermissionsSave(ai_requests=False, telegram_messages=False, response_decisions=False)
            else:
                try:
                    if type(data.get("version")) is not int or data["version"] != 1:
                        raise ValueError("Invalid permissions version")
                    selected = PermissionsSave.model_validate({key: value for key, value in data.items() if key != "version"})
                except ValueError as exc:
                    raise AdminError(503, "Saved dashboard permissions are unavailable") from exc
            return {"configured": data is not None, **selected.model_dump(),
                    "response_review_available": self.response_enabled,
                    "storage": self.store.status()}

    def require(self, capability):
        with self.lock:
            if not self.status()[capability]:
                raise AdminError(403, "This capability is disabled. Enable it in Setup → Permissions to continue")

    def save(self, body: PermissionsSave):
        with self.lock:
            if body.response_decisions and not self.response_enabled:
                raise AdminError(409, "Manual response review must first be enabled by the host operator")
            # Do not overwrite an unreadable or tampered permissions document.
            self.status()
            self.store.write("permissions", {"version": 1, **body.model_dump()})
            self.generation += 1
            return self.status()