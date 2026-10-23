from __future__ import annotations

from actions.base import Action, ActionParams
from catalog import CATALOG


class RegistryError(ValueError):
    pass


class ActionRegistry:
    """Maps catalog types to implementations. Only catalog types can be
    registered, one implementation each."""

    def __init__(self) -> None:
        self._actions: dict[str, Action] = {}

    def register(self, action: Action) -> None:
        action_type = getattr(action, "type", None)
        if action_type not in CATALOG:
            raise RegistryError(f"{action_type!r} is not in the action catalog (ADR 0006); it can't be registered")
        if action_type in self._actions:
            raise RegistryError(f"{action_type!r} is already registered")
        params_model = action.params_model
        if not issubclass(params_model, ActionParams):
            raise RegistryError(f"{action_type!r}: params_model must subclass ActionParams")
        self._actions[action_type] = action

    def get(self, action_type: str) -> Action | None:
        return self._actions.get(action_type)

    def types(self) -> frozenset[str]:
        return frozenset(self._actions)