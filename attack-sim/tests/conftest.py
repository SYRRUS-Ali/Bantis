"""Shared pytest fixtures for the attack-sim test suite."""

import pytest


@pytest.fixture(autouse=True)
def bantis_env_range_local(monkeypatch):
    """Every existing test assumes it's safe to instantiate and run any
    scenario. Scenario.__new__() now enforces BANTIS_ENV=range-local
    before allowing that (see scenarios/base.py) — set it by default so
    that assumption keeps holding everywhere except the guard's own
    tests (test_environment_guard.py), which override it deliberately.
    """
    monkeypatch.setenv("BANTIS_ENV", "range-local")
