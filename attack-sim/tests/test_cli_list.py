import cli


def test_list_shows_every_registered_scenario(capsys):
    exit_code = cli.main(["list"])

    assert exit_code == 0
    out = capsys.readouterr().out
    for scenario_id in (
        "malicious-dependency",
        "leaked-secret",
        "compromised-ci-step",
        "typosquatting",
        "noop",
    ):
        assert scenario_id in out


def test_list_shows_each_scenarios_mitre_technique(capsys):
    cli.main(["list"])

    out = capsys.readouterr().out
    assert "T1195.001" in out
    assert "T1552.001" in out
    assert "T1195.002" in out
    assert "N/A" in out


def test_list_output_is_sorted_alphabetically_by_scenario_id(capsys):
    cli.main(["list"])

    out = capsys.readouterr().out
    ids = [line.split()[0] for line in out.splitlines() if line.strip()]
    assert ids == sorted(ids)