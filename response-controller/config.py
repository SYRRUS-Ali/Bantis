from __future__ import annotations

import os
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

    def __post_init__(self) -> None:
        unknown = sorted(self.enabled_actions - CATALOG.keys())
        if unknown:
            raise ConfigError(f"enabled actions not in the catalog: {unknown}")


def from_env(env: dict[str, str] | None = None) -> ControllerConfig:
    env = os.environ if env is None else env
    state_dir = env.get("BANTIS_STATE_DIR", "")
    if not state_dir:
        raise ConfigError("BANTIS_STATE_DIR must be set: it holds the kill switch")
    enabled = frozenset(name.strip() for name in env.get("RESPONSE_ENABLED_ACTIONS", "").split(",") if name.strip())
    dry_run_raw = env.get("RESPONSE_DRY_RUN", "true").strip().lower()
    if dry_run_raw not in {"true", "false"}:
        raise ConfigError(f"RESPONSE_DRY_RUN must be 'true' or 'false', got {dry_run_raw!r}")
    return ControllerConfig(state_dir=Path(state_dir), enabled_actions=enabled, dry_run=dry_run_raw == "true")