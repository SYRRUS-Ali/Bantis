from __future__ import annotations

import json
import math
from urllib.parse import urlencode, urlsplit
from urllib.request import urlopen

from .core import validate_incident


class IncidentClient:
    def __init__(self, base_url: str, timeout: float = 5, page_size: int = 200):
        parsed = urlsplit(base_url)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            raise ValueError("Detection Engine URL must be http(s), without credentials, query, or fragment")
        if not math.isfinite(timeout) or timeout <= 0 or not 1 <= page_size <= 200:
            raise ValueError("timeout must be finite and positive; page size must be 1..200")
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.page_size = page_size

    def _scan(self) -> dict[str, dict]:
        offset = 0
        expected_total = None
        found: dict[str, dict] = {}
        while True:
            query = urlencode({"limit": self.page_size, "offset": offset})
            with urlopen(f"{self.base_url}/incidents?{query}", timeout=self.timeout) as response:
                page = json.load(response)
            if not isinstance(page, dict):
                raise ValueError("invalid incident page")
            total, items = page.get("total"), page.get("items")
            if (type(total) is not int or total < 0 or total > 1_000_000
                    or page.get("offset") != offset or page.get("limit") != self.page_size
                    or not isinstance(items, list) or len(items) != min(self.page_size, total - offset)):
                raise ValueError("incomplete or invalid incident page")
            if expected_total is not None and total != expected_total:
                raise ValueError("incident history changed during pagination; retry")
            expected_total = total
            for raw in items:
                incident = validate_incident(raw)
                if incident["incident_id"] in found:
                    raise ValueError("incident pagination repeated an ID; retry")
                found[incident["incident_id"]] = incident
            offset += len(items)
            if offset == total:
                return found

    def incidents(self) -> list[dict]:
        # The API uses offset pagination. Require two agreeing full scans so an
        # insertion/deletion shifting a page cannot silently create false gaps.
        first = self._scan()
        if first != self._scan():
            raise ValueError("incident history changed between scans; retry")
        return list(first.values())