import http.client
import json
from datetime import datetime
from urllib.parse import quote, urlencode, urlparse


class IncidentClient:
    def __init__(self, url: str, timeout: float = 10):
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("detection URL must be an http(s) base URL without credentials, query or fragment")
        self._url = parsed
        self._timeout = timeout

    def _get(self, path: str):
        cls = http.client.HTTPSConnection if self._url.scheme == "https" else http.client.HTTPConnection
        connection = cls(self._url.hostname, self._url.port, timeout=self._timeout)
        try:
            connection.request("GET", self._url.path.rstrip("/") + path, headers={"Accept": "application/json"})
            response = connection.getresponse()
            body = response.read()
            if response.status != 200:
                raise ValueError(f"detection-engine GET failed with HTTP {response.status}")
            return json.loads(body)
        except (OSError, http.client.HTTPException) as exc:
            raise ValueError(f"detection-engine GET failed ({type(exc).__name__})") from exc
        finally:
            connection.close()

    def incidents_since(self, since: datetime) -> list[dict]:
        result = {}
        offset = 0
        while True:
            page = self._get("/incidents?" + urlencode({"since": since.isoformat(), "limit": 200, "offset": offset}))
            if not isinstance(page, dict) or "items" not in page:
                raise ValueError("invalid detection-engine incident page")
            items = page.get("items")
            if not isinstance(items, list) or len(items) > 200:
                raise ValueError("invalid detection-engine incident page")
            if not all(isinstance(item, dict) and isinstance(item.get("incident_id"), str) for item in items):
                raise ValueError("invalid detection-engine incident identity")
            old_count = len(result)
            for item in items:
                result[item["incident_id"]] = item
            if len(items) < 200:
                return list(result.values())
            if len(result) == old_count:
                raise ValueError("detection-engine pagination made no progress")
            offset += 200

    def events(self, incident_id: str) -> list[dict]:
        result = self._get(f"/incidents/{quote(incident_id, safe='')}/events")
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise ValueError("invalid detection-engine evidence response")
        return result