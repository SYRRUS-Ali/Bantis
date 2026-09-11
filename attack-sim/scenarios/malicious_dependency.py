"""Scenario: Malicious Dependency Injection.

See docs/scenarios/malicious-dependency.md for the full writeup.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus

_REPO_ROOT = Path(__file__).resolve().parents[2]
_REQUIREMENTS_FILE = _REPO_ROOT / "range" / "api" / "requirements.txt"

_INJECTED_LINE = (
    "bantis-attack-sim-simulated-malicious-dependency==0.0.0"
    "  # BANTIS-ATTACK-SIM-INJECTED - safe to remove; written by the"
    " malicious-dependency scenario\n"
)

_BUILD_TIMEOUT_SECONDS = 180
_OUTPUT_TAIL_CHARS = 2000


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

        try:
            build = subprocess.run(
                ["docker", "compose", "build", "api"],
                cwd=_REPO_ROOT / "range",
                capture_output=True,
                text=True,
                timeout=_BUILD_TIMEOUT_SECONDS,
                check=False,
            )
        except FileNotFoundError:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="docker is not available in this environment",
                details={},
            )
        except subprocess.TimeoutExpired:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message=f"docker compose build did not finish within {_BUILD_TIMEOUT_SECONDS}s",
                details={},
            )

        output_tail = (build.stdout + build.stderr)[-_OUTPUT_TAIL_CHARS:]
        details = {
            "injected_package": _INJECTED_LINE.split("#", 1)[0].strip(),
            "build_returncode": build.returncode,
            "build_output_tail": output_tail,
        }

        if build.returncode == 0:
            return ScenarioResult(
                status=ScenarioStatus.SUCCESS,
                message="injected dependency was accepted — build succeeded",
                details=details,
            )

        return ScenarioResult(
            status=ScenarioStatus.FAILURE,
            message="injected dependency was rejected — build failed as expected",
            details=details,
        )

    def cleanup(self) -> None:
        if self._original_content is None:
            return
        _REQUIREMENTS_FILE.write_text(self._original_content)
        self._original_content = None
