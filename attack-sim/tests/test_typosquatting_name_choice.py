from pathlib import Path

import scenarios.typosquatting as ts

_REQUIREMENTS_FILE = Path(__file__).resolve().parents[2] / "range" / "api" / "requirements.txt"


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i] + [0] * len(b)
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current[j] = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
        previous = current
    return previous[-1]


def _real_dependency_names() -> list[str]:
    names = []
    for line in _REQUIREMENTS_FILE.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        name = line.split("==")[0].split("[")[0].strip().lower()
        names.append(name)
    return names


def test_impersonated_name_is_a_real_current_dependency():
    assert ts._IMPERSONATES in _real_dependency_names()


def test_fake_name_is_not_an_exact_match_of_any_real_dependency():
    assert ts._FAKE_PACKAGE_NAME not in _real_dependency_names()


def test_fake_name_is_a_plausible_near_miss_typo():
    distance = _levenshtein(ts._FAKE_PACKAGE_NAME, ts._IMPERSONATES)
    assert 1 <= distance <= 2