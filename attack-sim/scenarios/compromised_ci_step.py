from __future__ import annotations

from pathlib import Path

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus
from scenarios.replay import register

_REPO_ROOT = Path(__file__).resolve().parents[2]
_WORKFLOW_FILE = _REPO_ROOT / ".github" / "workflows" / "ci.yml"

_STEP_MARKER = "BANTIS-ATTACK-SIM-INJECTED"

_INJECTED_STEP = (
    f"      - name: {_STEP_MARKER} - Suspicious Execution Marker\n"
    '        run: echo "::warning::BANTIS-ATTACK-SIM suspicious execution'
    ' detected — safe to remove; written by the compromised-ci-step'
    ' scenario"\n'
)

_STEPS_ANCHOR = "    steps:\n"

@register
class CompromisedCiStepScenario(Scenario):
    name = "compromised-ci-step"
    mitre_technique = "T1195.002"

    def __init__(self) -> None:
        self._original_content: str | None = None

    def run(self) -> ScenarioResult:
        if not _WORKFLOW_FILE.is_file():
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="ci.yml not found",
                details={"path": str(_WORKFLOW_FILE)},
            )

        original = _WORKFLOW_FILE.read_text()
        if _STEP_MARKER in original:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="ci.yml already contains the injected step — run cleanup() first",
                details={"path": str(_WORKFLOW_FILE)},
            )

        anchor_index = original.find(_STEPS_ANCHOR)
        if anchor_index == -1:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="could not find a job's steps: block to inject into",
                details={"path": str(_WORKFLOW_FILE)},
            )

        self._original_content = original
        insertion_point = anchor_index + len(_STEPS_ANCHOR)
        _WORKFLOW_FILE.write_text(
            original[:insertion_point] + _INJECTED_STEP + original[insertion_point:]
        )

        return ScenarioResult(
            status=ScenarioStatus.SUCCESS,
            message="injected a step that only logs suspicious execution — no real pipeline effect",
            details={"artifact": _STEP_MARKER, "path": str(_WORKFLOW_FILE)},
        )

    def cleanup(self) -> None:
        if self._original_content is not None:
            _WORKFLOW_FILE.write_text(self._original_content)
            self._original_content = None
            return

        if _WORKFLOW_FILE.is_file():
            current = _WORKFLOW_FILE.read_text()
            if _INJECTED_STEP in current:
                _WORKFLOW_FILE.write_text(current.replace(_INJECTED_STEP, ""))