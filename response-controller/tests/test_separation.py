"""The controller must never read model output (design, Principle 1):
nothing here may import the AI provider's SDK or any ai-copilot module."""

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_COPILOT = _ROOT.parent / "ai-copilot"
_SOURCES = [p for p in _ROOT.rglob("*.py") if "tests" not in p.relative_to(_ROOT).parts]


def _imports():
    for path in _SOURCES:
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                yield from ((path.name, a.name.split(".")[0]) for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                yield path.name, node.module.split(".")[0]


def test_nothing_imports_the_ai_providers_sdk():
    assert [i for i in _imports() if i[1] == "anthropic"] == []


def test_nothing_imports_an_ai_copilot_module():
    copilot = {p.stem for p in _COPILOT.glob("*.py")} | {"providers", "eval"}
    own = {p.stem for p in _ROOT.glob("*.py")} | {"actions"}
    assert copilot, "ai-copilot modules not found"
    assert [i for i in _imports() if i[1] in copilot - own] == []


def test_nothing_reaches_into_another_component_through_sys_path():
    for path in _SOURCES:
        if path.name == "conftest.py":
            continue
        text = path.read_text()
        assert "ai-copilot" not in text, path
        assert "sys.path" not in text, path