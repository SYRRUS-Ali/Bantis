from types import SimpleNamespace

import cli
import scenarios.malicious_dependency as md


def test_run_noop_succeeds_and_returns_exit_code_zero(capsys):
    exit_code = cli.main(["run", "noop"])

    assert exit_code == 0
    assert "success" in capsys.readouterr().out


def test_run_unknown_scenario_prints_error_and_returns_exit_code_one(capsys):
    exit_code = cli.main(["run", "does-not-exist"])

    assert exit_code == 1
    assert "unknown scenario_id" in capsys.readouterr().err


def test_run_real_scenario_reflects_its_result_and_cleans_up(tmp_path, monkeypatch, capsys):
    requirements_file = tmp_path / "requirements.txt"
    requirements_file.write_text("fastapi==0.120.0\n")
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", requirements_file)
    monkeypatch.setattr(
        md.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=1, stdout="", stderr="no matching distribution"),
    )

    exit_code = cli.main(["run", "malicious-dependency"])

    assert exit_code == 0
    assert "failure" in capsys.readouterr().out
    assert requirements_file.read_text() == "fastapi==0.120.0\n"


def test_run_returns_exit_code_one_on_scenario_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(md, "_REQUIREMENTS_FILE", tmp_path / "missing.txt")

    exit_code = cli.main(["run", "malicious-dependency"])

    assert exit_code == 1
    assert "error" in capsys.readouterr().out.lower()