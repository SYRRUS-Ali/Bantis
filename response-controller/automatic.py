"""Shared checks for durable automatic-execution reservations."""

from datetime import datetime, timedelta


class AutomaticLimit(ValueError):
    """The rolling hourly automatic-attempt budget is exhausted."""


class AutomaticDuplicate(ValueError):
    """This action or incident has already reserved an automatic attempt."""


def check_reservation(entries: list[dict], entry: dict, maximum: int) -> None:
    reservations = [item for item in entries if item["event"] == "automatic_reserved"]
    if any(item["action_id"] == entry["action_id"] or item["incident_id"] == entry["incident_id"]
           for item in reservations):
        raise AutomaticDuplicate("an automatic attempt was already reserved for this action or incident")
    cutoff = datetime.fromisoformat(entry["reserved_at"]) - timedelta(hours=1)
    # Future reservations also count: rolling the host clock back must not open a new budget.
    if sum(datetime.fromisoformat(item["reserved_at"]) > cutoff for item in reservations) >= maximum:
        raise AutomaticLimit(f"automatic execution limit reached ({maximum} attempts per rolling hour)")