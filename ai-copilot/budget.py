from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from decision_log import DecisionLog, TokenUsage
from models import AttemptRecord

DEFAULT_MAX_TOKENS_PER_DAY = 500_000

Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def start_of_utc_day(moment: datetime) -> datetime:
    return moment.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


@dataclass(frozen=True)
class BudgetStatus:
    used: TokenUsage
    limit: int | None
    now: datetime

    @property
    def resets_at(self) -> datetime:
        return start_of_utc_day(self.now) + timedelta(days=1)

    @property
    def exhausted(self) -> bool:
        return self.limit is not None and self.used.total_tokens >= self.limit

    @property
    def remaining(self) -> int | None:
        return None if self.limit is None else max(self.limit - self.used.total_tokens, 0)

    @property
    def seconds_until_reset(self) -> int:
        return max(int((self.resets_at - self.now).total_seconds()) + 1, 1)


@dataclass
class TokenBudget:
    max_tokens_per_day: int | None = DEFAULT_MAX_TOKENS_PER_DAY
    decision_log: DecisionLog | None = None
    clock: Clock = _utc_now
    _in_memory: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.max_tokens_per_day is not None and self.max_tokens_per_day < 1:
            raise ValueError("max_tokens_per_day must be at least 1, or None for no budget")

    def status(self) -> BudgetStatus:
        now = self.clock()
        day = start_of_utc_day(now)
        if self.decision_log is not None:
            used = self.decision_log.token_usage_between(day, day + timedelta(days=1))
        else:
            used = self._in_memory.get(day, TokenUsage()).model_copy()
        return BudgetStatus(used=used, limit=self.max_tokens_per_day, now=now)

    def record(self, attempts: list[AttemptRecord]) -> None:
        if self.decision_log is not None:
            return
        day = start_of_utc_day(self.clock())
        usage = self._in_memory.setdefault(day, TokenUsage())
        usage.add_attempts([attempt.model_dump() for attempt in attempts])