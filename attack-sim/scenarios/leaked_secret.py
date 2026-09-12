from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus

_SCAN_TIMEOUT_SECONDS = 60
_OUTPUT_TAIL_CHARS = 2000

_LEAKED_FILE_NAME = "config.py"

_FAKE_AWS_ACCESS_KEY_ID = "AKIAFAKEBANTISATSIM1"
_FAKE_AWS_SECRET_ACCESS_KEY = "FAKE/BANTIS-ATTACK-SIM/DO-NOT-USE/NOT-REAL"

_LEAKED_FILE_CONTENT = (
    f'AWS_ACCESS_KEY_ID = "{_FAKE_AWS_ACCESS_KEY_ID}"\n'
    f'AWS_SECRET_ACCESS_KEY = "{_FAKE_AWS_SECRET_ACCESS_KEY}"\n'
)


class LeakedSecretScenario(Scenario):
    name = "leaked-secret"
    mitre_technique = "T1552.001"

    def __init__(self) -> None:
        self._workdir: Path | None = None

    def run(self) -> ScenarioResult:
        if self._workdir is not None:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="a previous run's scratch repo is still present — run cleanup() first",
                details={"path": str(self._workdir)},
            )

        self._workdir = Path(tempfile.mkdtemp(prefix="bantis-leaked-secret-"))
        workdir = self._workdir

        init = subprocess.run(
            ["git", "init", "-q"],
            cwd=workdir,
            capture_output=True,
            text=True,
            check=False,
        )
        if init.returncode != 0:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="failed to initialize the scratch git repo",
                details={"stderr": init.stderr},
            )

        subprocess.run(
            ["git", "config", "user.email", "attack-sim@bantis.local"],
            cwd=workdir, capture_output=True, text=True, check=False,
        )
        subprocess.run(
            ["git", "config", "user.name", "bantis-attack-sim"],
            cwd=workdir, capture_output=True, text=True, check=False,
        )

        (workdir / _LEAKED_FILE_NAME).write_text(_LEAKED_FILE_CONTENT)

        subprocess.run(
            ["git", "add", _LEAKED_FILE_NAME],
            cwd=workdir, capture_output=True, text=True, check=False,
        )
        commit = subprocess.run(
            ["git", "commit", "-q", "-m", "feat: add AWS config"],
            cwd=workdir, capture_output=True, text=True, check=False,
        )
        if commit.returncode != 0:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="failed to create the scratch commit carrying the fake secret",
                details={"stderr": commit.stderr},
            )

        try:
            scan = subprocess.run(
                ["gitleaks", "git", str(workdir), "--verbose"],
                capture_output=True,
                text=True,
                timeout=_SCAN_TIMEOUT_SECONDS,
                check=False,
            )
        except FileNotFoundError:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="gitleaks is not available in this environment",
                details={},
            )
        except subprocess.TimeoutExpired:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message=f"gitleaks scan did not finish within {_SCAN_TIMEOUT_SECONDS}s",
                details={},
            )

        output_tail = (scan.stdout + scan.stderr)[-_OUTPUT_TAIL_CHARS:]
        details = {
            "leaked_file": _LEAKED_FILE_NAME,
            "gitleaks_returncode": scan.returncode,
            "gitleaks_output_tail": output_tail,
        }

        if scan.returncode == 0:
            return ScenarioResult(
                status=ScenarioStatus.SUCCESS,
                message="committed secret went undetected — leak was not caught",
                details=details,
            )
        if scan.returncode == 1:
            return ScenarioResult(
                status=ScenarioStatus.FAILURE,
                message="committed secret was caught by gitleaks as expected",
                details=details,
            )
        return ScenarioResult(
            status=ScenarioStatus.ERROR,
            message=f"gitleaks exited with an unexpected code ({scan.returncode})",
            details=details,
        )

    def cleanup(self) -> None:
        if self._workdir is not None:
            shutil.rmtree(self._workdir, ignore_errors=True)
            self._workdir = None