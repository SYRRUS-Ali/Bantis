import asyncio
from datetime import datetime, timezone

from .detection import DetectionClient, UpstreamError


class LiveFeed:
    """One bounded event window shared by all connected dashboard sessions."""

    def __init__(self, detection: DetectionClient, interval: float):
        self.detection = detection
        self.interval = interval
        self.changed = asyncio.Condition()
        self.snapshot = {
            "type": "events.snapshot",
            "sequence": 0,
            "status": "connecting",
            "observed_at": None,
            "last_success_at": None,
            "total": None,
            "limit": 500,
            "items": [],
            "gap_possible": False,
            "poll_seconds": interval,
        }

    async def poll(self):
        previous = self.snapshot
        now = datetime.now(timezone.utc).isoformat()
        try:
            page = await self.detection.live_events()
            # A bounded window cannot claim continuous coverage when no old ID
            # remains after a poll, or more events arrived than it can retain.
            old_ids = {event["event_id"] for event in previous["items"]}
            new_ids = {event.event_id for event in page.items}
            gap = previous["gap_possible"] or bool(
                previous["total"] is not None
                and (
                    page.total < previous["total"]
                    or page.total - previous["total"] > page.limit
                    or (old_ids and new_ids and old_ids.isdisjoint(new_ids))
                )
            )
            update = {
                "status": "available",
                "last_success_at": now,
                "total": page.total,
                "limit": page.limit,
                "items": [event.model_dump(mode="json") for event in page.items],
                "gap_possible": gap,
            }
        except UpstreamError:
            update = {"status": "unavailable"}
        async with self.changed:
            self.snapshot = {
                **previous,
                **update,
                "sequence": previous["sequence"] + 1,
                "observed_at": now,
            }
            self.changed.notify_all()

    async def run(self):
        while True:
            await self.poll()
            await asyncio.sleep(self.interval)