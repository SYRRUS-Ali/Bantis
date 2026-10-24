from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

OPERATOR_FILE = "kill-switch"
TRIPWIRE_FILE = "kill-switch.tripped"


class Level(StrEnum):
    CLEAR = "clear"
    AUTO_OFF = "auto-off"
    EXECUTION_OFF = "execution-off"


_RANK = {Level.CLEAR: 0, Level.AUTO_OFF: 1, Level.EXECUTION_OFF: 2}


@dataclass(frozen=True)
class SwitchState:
    level: Level
    ai_off: bool
    reasons: tuple[str, ...]

    @property
    def execution_allowed(self) -> bool:
        return self.level != Level.EXECUTION_OFF

    @property
    def auto_allowed(self) -> bool:
        return self.level == Level.CLEAR


_HALT_ALL = Level.EXECUTION_OFF


def _parse(path: Path) -> tuple[Level, bool, str]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise TypeError("not a JSON object")
    level = Level(data["level"])
    ai_off = data.get("ai_off", False)
    if not isinstance(ai_off, bool):
        raise TypeError("ai_off must be true or false")
    return level, ai_off, str(data.get("reason", ""))


def read_state(state_dir: str | os.PathLike) -> SwitchState:
    state_dir = Path(state_dir)
    operator = state_dir / OPERATOR_FILE
    tripwire = state_dir / TRIPWIRE_FILE
    try:
        level, ai_off, reason = _parse(operator)
    except Exception as exc:  # missing, unreadable, malformed, unknown level: all mean stop
        return SwitchState(_HALT_ALL, True, (f"kill switch unreadable ({type(exc).__name__}: {exc}); failing closed",))
    reasons = [f"operator: {level.value}" + (f" ({reason})" if reason else "")]

    try:
        tripped = tripwire.exists()
    except OSError as exc:
        return SwitchState(_HALT_ALL, True, (f"tripwire state unreadable ({exc}); failing closed",))
    if tripped:
        try:
            trip_level, trip_ai_off, trip_reason = _parse(tripwire)
        except Exception as exc:
            return SwitchState(_HALT_ALL, True, (f"tripwire state unreadable ({type(exc).__name__}: {exc}); failing closed",))
        if _RANK[trip_level] > _RANK[level]:
            level = trip_level
        ai_off = ai_off or trip_ai_off
        reasons.append(f"tripwire: {trip_level.value}" + (f" ({trip_reason})" if trip_reason else ""))
    return SwitchState(level, ai_off, tuple(reasons))


def _write(path: Path, level: Level, ai_off: bool, reason: str, set_by: str) -> None:
    body = {
        "level": level.value,
        "ai_off": ai_off,
        "reason": reason,
        "set_by": set_by,
        "set_at": datetime.now(UTC).isoformat(),
    }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(body))
    os.replace(tmp, path)  # atomic: a reader sees the old state or the new one, never half a file


def engage(state_dir: str | os.PathLike, level: Level, reason: str, set_by: str, ai_off: bool = False) -> None:
    """The operator's stop. Never lowers the current operator level."""
    if not reason.strip():
        raise ValueError("a reason is required")
    path = Path(state_dir) / OPERATOR_FILE
    try:
        current_level, current_ai_off, _ = _parse(path)
    except Exception:
        current_level, current_ai_off = Level.CLEAR, False
    if _RANK[current_level] > _RANK[level]:
        level = current_level
    _write(path, level, ai_off or current_ai_off, reason, set_by)


def trip(state_dir: str | os.PathLike, level: Level, reason: str, ai_off: bool = False) -> None:
    """A tripwire. Can only add restriction to what's already tripped."""
    if level == Level.CLEAR:
        raise ValueError("a tripwire can engage the switch, never clear it")
    path = Path(state_dir) / TRIPWIRE_FILE
    try:
        current_level, current_ai_off, _ = _parse(path)
    except FileNotFoundError:
        current_level, current_ai_off = Level.CLEAR, False
    except Exception:
        current_level, current_ai_off = Level.EXECUTION_OFF, True
    if _RANK[current_level] > _RANK[level]:
        level = current_level
    _write(path, level, ai_off or current_ai_off, reason, "tripwire")