from __future__ import annotations

import http.client
import json
import urllib.parse
from datetime import datetime

_ALLOWED_URL_SCHEMES = {"http", "https"}
_PAGE_SIZE = 200  # detection-engine's own maximum for GET /incidents


class DetectionEngineError(RuntimeError):
    pass


class DetectionEngineClient:
    def __init__(self, base_url: str, timeout: float = 10.0) -> None:
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in _ALLOWED_URL_SCHEMES:
            raise ValueError(f"detection-engine URL must be http or https, got {parsed.scheme!r} in {base_url!r}")
        self._is_https = parsed.scheme == "https"
        self._host = parsed.hostname
        self._port = parsed.port or (443 if self._is_https else 80)
        self._base_path = parsed.path.rstrip("/")
        self._timeout = timeout

    def _get(self, path: str, params: dict | None = None):
        query = f"?{urllib.parse.urlencode(params)}" if params else ""
        connection_cls = http.client.HTTPSConnection if self._is_https else http.client.HTTPConnection
        connection = connection_cls(self._host, self._port, timeout=self._timeout)
        try:
            connection.request("GET", f"{self._base_path}{path}{query}", headers={"Accept": "application/json"})
            response = connection.getresponse()
            body = response.read()
        except (OSError, http.client.HTTPException) as exc:
            raise DetectionEngineError(f"GET {path} failed: {exc}") from exc
        finally:
            connection.close()

        if response.status != 200:
            raise DetectionEngineError(f"GET {path} returned HTTP {response.status}")
        return json.loads(body)

    def list_incidents_since(self, since: datetime) -> list[dict]:
        incidents: dict[str, dict] = {}
        offset = 0
        while True:
            page = self._get(
                "/incidents", {"since": since.isoformat(), "limit": _PAGE_SIZE, "offset": offset}
            )
            for item in page["items"]:
                incidents.setdefault(item["incident_id"], item)
            if len(page["items"]) < _PAGE_SIZE:
                return list(incidents.values())
            offset += _PAGE_SIZE

    def get_incident_events(self, incident_id: str) -> list[dict]:
        return self._get(f"/incidents/{urllib.parse.quote(incident_id, safe='')}/events")