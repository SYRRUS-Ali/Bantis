from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from catalog import CATALOG


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ControllerConfig:
    state_dir: Path
    enabled_actions: frozenset[str] = field(default_factory=frozenset)  # G5: nothing by default
    dry_run: bool = True  # every phase starts by recording, not acting
    automatic_action: str = ""
    automatic_repo: str = ""
    automatic_policy_rule: str = "A3:composite-success"
    automatic_max_per_hour: int = 5

    def __post_init__(self) -> None:
        unknown = sorted(self.enabled_actions - CATALOG.keys())
        if unknown:
            raise ConfigError(f"enabled actions not in the catalog: {unknown}")
        if self.automatic_action not in {"", "hold_promotion"}:
            raise ConfigError("RESPONSE_AUTO_ACTION may only be hold_promotion")
        if type(self.automatic_max_per_hour) is not int or not 1 <= self.automatic_max_per_hour <= 5:
            raise ConfigError("RESPONSE_AUTO_MAX_PER_HOUR must be an integer from 1 to 5")
        if self.automatic_action:
            if self.automatic_action not in self.enabled_actions:
                raise ConfigError("the automatic action must also be in RESPONSE_ENABLED_ACTIONS")
            if not re.fullmatch(r"[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}", self.automatic_repo):
                raise ConfigError("RESPONSE_AUTO_REPO must name one repository as owner/name")
            if not self.automatic_policy_rule.strip():
                raise ConfigError("RESPONSE_AUTO_POLICY_RULE must be nonempty")
        elif self.automatic_repo:
            raise ConfigError("RESPONSE_AUTO_REPO requires RESPONSE_AUTO_ACTION")


def from_env(env: dict[str, str] | None = None) -> ControllerConfig:
    env = os.environ if env is None else env
    state_dir = env.get("BANTIS_STATE_DIR", "")
    if not state_dir:
        raise ConfigError("BANTIS_STATE_DIR must be set: it holds the kill switch")
    enabled = frozenset(name.strip() for name in env.get("RESPONSE_ENABLED_ACTIONS", "").split(",") if name.strip())
    dry_run_raw = env.get("RESPONSE_DRY_RUN", "true").strip().lower()
    if dry_run_raw not in {"true", "false"}:
        raise ConfigError(f"RESPONSE_DRY_RUN must be 'true' or 'false', got {dry_run_raw!r}")
    try:
        maximum = int(env.get("RESPONSE_AUTO_MAX_PER_HOUR", "5"))
    except ValueError as exc:
        raise ConfigError("RESPONSE_AUTO_MAX_PER_HOUR must be an integer from 1 to 5") from exc
    return ControllerConfig(state_dir=Path(state_dir), enabled_actions=enabled, dry_run=dry_run_raw == "true",
                            automatic_action=env.get("RESPONSE_AUTO_ACTION", "").strip(),
                            automatic_repo=env.get("RESPONSE_AUTO_REPO", "").strip(),
                            automatic_policy_rule=env.get("RESPONSE_AUTO_POLICY_RULE", "A3:composite-success"),
                            automatic_max_per_hour=maximum)