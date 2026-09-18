from types import SimpleNamespace

import pytest

import scenarios.malicious_dependency as md
from fingerprint_utils import fingerprint
from scenarios.base import ScenarioStatus

_EXPECTED_FINGERPRINT = (
    ("artifact", "str"),
    ("tool_output_tail", "str"),
    ("tool_returncode", "int"),
)


@pytest.fixture
def requirements_file(tmp_path, monkeypatch):
    path = tmp_path / "requirements.txt"
    path.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", path)
    return path


@pytest.mark.fingerprint
def test_malicious_dependency_fingerprint_is_stable(requirements_file, monkeypatch):
    monkeypatch.setattr(
        md.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution"),
    )

    result = md.MaliciousDependencyScenario().run()

    assert result.status == ScenarioStatus.FAILURE
    assert fingerprint(result.details) == _EXPECTED_FINGERPRINT