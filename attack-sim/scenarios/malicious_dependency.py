"""Scenario: Malicious Dependency Injection.

See docs/scenarios/malicious-dependency.md for the full writeup.
"""

from __future__ import annotations

from pathlib import Path

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REQUIREMENTS_FILE = _REPO_ROOT / "range" / "api" / "requirements.txt"

_INJECTED_LINE = (
    "bantis-attack-sim-simulated-malicious-dependency==0.0.0"
    "  # BANTIS-ATTACK-SIM-INJECTED - safe to remove; written by the"
    " malicious-dependency scenario\n"
)


class MaliciousDependencyScenario(Scenario):
    name = "malicious-dependency"
    mitre_technique = "T1195.001"

    def __init__(self) -> None:
        self._original_content: str | None = None

    def run(self) -> ScenarioResult:
        if not _REQUIREMENTS_FILE.is_file():
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="requirements.txt not found",
                details={"path": str(_REQUIREMENTS_FILE)},
            )

        original = _REQUIREMENTS_FILE.read_text()
        if _INJECTED_LINE in original:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="requirements.txt already contains the injected line — run cleanup() first",
                details={"path": str(_REQUIREMENTS_FILE)},
            )

        self._original_content = original
        # requirements.txt isn't guaranteed to end with a newline — appending
        # blindly would otherwise glue the injected line onto the end of the
        # last existing one, producing an invalid requirement string instead
        # of a second line.
        separator = "" if original == "" or original.endswith("\n") else "\n"
        _REQUIREMENTS_FILE.write_text(original + separator + _INJECTED_LINE)

        return ScenarioResult(
            status=ScenarioStatus.SUCCESS,
            message="malicious dependency line injected",
            details={"injected_package": _INJECTED_LINE.split("#", 1)[0].strip()},
        )

    def cleanup(self) -> None:
        if self._original_content is None:
            return
        _REQUIREMENTS_FILE.write_text(self._original_content)
        self._original_content = None
