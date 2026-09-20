from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from scenarios.base import Scenario, ScenarioResult, ScenarioStatus, logger
from scenarios.replay import register

_FAKE_PACKAGE_NAME = "redsi"
_FAKE_PACKAGE_VERSION = "0.0.1"
_IMPERSONATES = "redis"

_INSTALL_TIMEOUT_SECONDS = 60
_OUTPUT_TAIL_CHARS = 2000


def _build_fake_wheel(dest_dir: Path, name: str, version: str) -> Path:
    dist_info = f"{name}-{version}.dist-info"
    wheel_path = dest_dir / f"{name}-{version}-py3-none-any.whl"

    files = {
        f"{name}/__init__.py": (
            "# BANTIS-ATTACK-SIM inert typosquatting marker — this package"
            " intentionally does nothing at import time.\n"
        ),
        f"{dist_info}/METADATA": (
            "Metadata-Version: 2.1\n"
            f"Name: {name}\n"
            f"Version: {version}\n"
            "Summary: Bantis attack-sim typosquatting marker package (inert).\n"
        ),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: bantis-attack-sim\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ),
    }

    record_lines = []
    with zipfile.ZipFile(wheel_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for arcname, content in files.items():
            data = content.encode("utf-8")
            zf.writestr(arcname, data)
            digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            record_lines.append(f"{arcname},sha256={digest},{len(data)}")
        record_lines.append(f"{dist_info}/RECORD,,")
        zf.writestr(f"{dist_info}/RECORD", "\n".join(record_lines) + "\n")

    return wheel_path


@register
class TyposquattingScenario(Scenario):
    name = "typosquatting"
    mitre_technique = "T1195.001"

    def __init__(self) -> None:
        self._workdir: Path | None = None

    def run(self) -> ScenarioResult:
        if self._workdir is not None:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message="a previous run's scratch install is still present — run cleanup() first",
                details={"path": str(self._workdir)},
            )

        self._workdir = Path(tempfile.mkdtemp(prefix="bantis-typosquatting-"))
        workdir = self._workdir
        index_dir = workdir / "fake-index"
        install_dir = workdir / "installed"
        index_dir.mkdir()
        install_dir.mkdir()

        wheel_path = _build_fake_wheel(index_dir, _FAKE_PACKAGE_NAME, _FAKE_PACKAGE_VERSION)

        try:
            install = subprocess.run(
                [
                    sys.executable, "-m", "pip", "install",
                    "--no-index",  # never resolve against the real PyPI
                    "--find-links", str(index_dir),  # only this scratch dir
                    "--target", str(install_dir),  # isolated dir, never site-packages
                    f"{_FAKE_PACKAGE_NAME}=={_FAKE_PACKAGE_VERSION}",
                ],
                capture_output=True,
                text=True,
                timeout=_INSTALL_TIMEOUT_SECONDS,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ScenarioResult(
                status=ScenarioStatus.ERROR,
                message=f"pip install did not finish within {_INSTALL_TIMEOUT_SECONDS}s",
                details={},
            )

        output_tail = (install.stdout + install.stderr)[-_OUTPUT_TAIL_CHARS:]
        details = {
            "artifact": f"{_FAKE_PACKAGE_NAME}=={_FAKE_PACKAGE_VERSION}",
            "impersonates": _IMPERSONATES,
            "tool_returncode": install.returncode,
            "tool_output_tail": output_tail,
            "install_target": str(install_dir),
            "wheel_path": str(wheel_path),
        }

        if install.returncode == 0:
            return ScenarioResult(
                status=ScenarioStatus.SUCCESS,
                message="typosquatted package installed — no name-similarity check caught it",
                details=details,
            )

        return ScenarioResult(
            status=ScenarioStatus.FAILURE,
            message="typosquatted package install was rejected",
            details=details,
        )

    def cleanup(self) -> None:
        if self._workdir is not None:
            workdir = self._workdir
            self._workdir = None
            try:
                shutil.rmtree(workdir)
            except OSError:
                logger.warning(
                    "failed to remove scratch install — it still contains the typosquatted package",
                    extra={"scenario": self.name, "path": str(workdir)},
                )
                raise