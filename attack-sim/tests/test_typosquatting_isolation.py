import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

import scenarios.typosquatting as ts

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_install_command_never_hits_the_real_package_index(monkeypatch):
    seen_cmd = {}
    real_run = subprocess.run

    def spy_run(cmd, **kwargs):
        seen_cmd["cmd"] = cmd
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ts.subprocess, "run", spy_run)

    scenario = ts.TyposquattingScenario()
    scenario.run()
    scenario.cleanup()

    cmd = seen_cmd["cmd"]
    assert "--no-index" in cmd
    assert "--find-links" in cmd
    find_links_dir = Path(cmd[cmd.index("--find-links") + 1])
    assert Path(tempfile.gettempdir()) in find_links_dir.resolve().parents


def test_install_target_is_isolated_under_the_system_temp_dir():
    scenario = ts.TyposquattingScenario()
    result = scenario.run()

    install_target = Path(result.details["install_target"]).resolve()
    assert Path(tempfile.gettempdir()) in install_target.parents
    assert _REPO_ROOT not in install_target.parents and install_target != _REPO_ROOT

    scenario.cleanup()


def test_installed_package_is_never_importable_in_this_process():
    paths_before = list(sys.path)

    scenario = ts.TyposquattingScenario()
    scenario.run()

    assert sys.path == paths_before
    assert ts._FAKE_PACKAGE_NAME not in sys.modules

    scenario.cleanup()


def test_cleanup_leaves_no_trace_of_the_installed_package_on_disk():
    scenario = ts.TyposquattingScenario()
    result = scenario.run()
    install_target = Path(result.details["install_target"])
    assert (install_target / ts._FAKE_PACKAGE_NAME).is_dir()

    scenario.cleanup()

    assert not install_target.exists()
    assert scenario._workdir is None


def test_wheel_contains_no_build_hooks_or_executable_code_paths():
    scenario = ts.TyposquattingScenario()
    result = scenario.run()

    with zipfile.ZipFile(result.details["wheel_path"]) as zf:
        names = zf.namelist()

    assert not any(n.endswith(("setup.py", "setup.cfg", "pyproject.toml")) for n in names)
    assert any(n.endswith("__init__.py") for n in names)

    scenario.cleanup()