import scenarios.compromised_ci_step as ccs

_DANGEROUS_PATTERNS = (
    "curl", "wget", "secrets.", "nc ", "ncat", "/dev/tcp", "base64 -d", "eval",
)


def _run_line() -> str:
    return next(line for line in ccs._INJECTED_STEP.splitlines() if line.strip().startswith("run:"))


def test_injected_step_only_echoes_a_log_line():
    assert _run_line().strip().startswith("run: echo ")


def test_injected_step_touches_no_secrets_or_network():
    lowered = ccs._INJECTED_STEP.lower()
    for pattern in _DANGEROUS_PATTERNS:
        assert pattern not in lowered, f"unexpected dangerous pattern found: {pattern!r}"


def test_injected_step_is_clearly_marked_as_a_simulated_marker():
    assert ccs._STEP_MARKER in ccs._INJECTED_STEP
    assert "suspicious execution" in ccs._INJECTED_STEP.lower()