from __future__ import annotations

from enum import StrEnum


class Tier(StrEnum):
    AUTO = "A"  # may run without approval, unless the kill switch is at auto-off
    APPROVAL = "B"  # never runs without an approval bound to the exact proposal


CATALOG: dict[str, Tier] = {
    "preserve_evidence": Tier.AUTO,
    "notify_channel": Tier.AUTO,
    "hold_promotion": Tier.AUTO,
    "rollback_latest": Tier.APPROVAL,
    "block_client_ip": Tier.APPROVAL,
    "lift_promotion_hold": Tier.APPROVAL,
}

# Each action's undo, where it has one. Purely additive actions have none.
UNDO: dict[str, str | None] = {
    "preserve_evidence": None,
    "notify_channel": None,
    "hold_promotion": "lift_promotion_hold",
    "rollback_latest": "rollback_latest",
    "block_client_ip": None,  # rules carry an expiry; removal is part of the action's own design
    "lift_promotion_hold": "hold_promotion",
}

ADDITIVE = frozenset({"preserve_evidence", "notify_channel"})