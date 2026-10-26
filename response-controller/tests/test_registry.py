import pytest
from helpers import FakeAction
from pydantic import BaseModel, ValidationError

from actions.base import ActionParams
from registry import ActionRegistry, RegistryError


def test_only_catalog_types_can_be_registered():
    with pytest.raises(RegistryError, match="not in the action catalog"):
        ActionRegistry().register(FakeAction("revoke_credentials"))


def test_a_type_is_registered_once():
    registry = ActionRegistry()
    registry.register(FakeAction())
    with pytest.raises(RegistryError, match="already registered"):
        registry.register(FakeAction())


def test_params_must_use_the_strict_base():
    class Loose(BaseModel):
        variable: str

    action = FakeAction()
    action.params_model = Loose
    with pytest.raises(RegistryError, match="ActionParams"):
        ActionRegistry().register(action)


def test_the_strict_base_forbids_extras_and_coercion():
    class P(ActionParams):
        count: int

    with pytest.raises(ValidationError):
        P.model_validate({"count": 1, "extra": "x"})
    with pytest.raises(ValidationError):
        P.model_validate({"count": "1"})