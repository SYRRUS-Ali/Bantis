import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SOURCES = sorted(
    p for p in _ROOT.rglob("*.py") if not ({"tests", "eval", "examples", ".venv"} & set(p.relative_to(_ROOT).parts))
)

_FORBIDDEN_MODULES = {"subprocess", "requests", "httpx", "urllib.request", "paramiko", "docker", "pty", "telnetlib", "ftplib", "smtplib"}
_FORBIDDEN_CALLS = {("os", "system"), ("os", "popen"), ("os", "execv"), ("os", "execve"), ("os", "execvp"), ("os", "spawnv"), ("os", "kill")}


def _trees():
    return [(path.relative_to(_ROOT), ast.parse(path.read_text(), filename=str(path))) for path in _SOURCES]


def test_the_scan_covers_the_component():
    names = {str(p) for p, _ in _trees()}

    assert {"worker.py", "api.py", "detection_client.py", "providers/claude.py"} <= names


def test_nothing_imports_a_way_to_run_commands_or_make_other_requests():
    found = []
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found += [(str(path), a.name) for a in node.names if a.name in _FORBIDDEN_MODULES]
            elif isinstance(node, ast.ImportFrom) and node.module in _FORBIDDEN_MODULES:
                found.append((str(path), node.module))

    assert found == []


def test_nothing_runs_a_process():
    found = []
    for path, tree in _trees():
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and (node.func.value.id, node.func.attr) in _FORBIDDEN_CALLS
            ):
                found.append((str(path), f"{node.func.value.id}.{node.func.attr}"))

    assert found == []


def test_the_only_request_to_detection_engine_is_a_read():
    """The Copilot reads incidents; it never writes events, incidents,
    confidence or anything else back.
    """
    methods = []
    for path, tree in _trees():
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "request":
                first = node.args[0] if node.args else None
                methods.append((str(path), first.value if isinstance(first, ast.Constant) else ast.unparse(first)))

    assert methods == [("detection_client.py", "GET")]


def test_the_api_offers_no_way_to_act_on_an_incident(tmp_path):
    from fastapi.routing import APIRoute

    from api import create_app
    from decision_log import DecisionLog
    from providers.base import UnavailableProvider

    app = create_app(DecisionLog(tmp_path / "d.db"), UnavailableProvider("test"), "x" * 16)
    routes = {(m, r.path) for r in app.routes if isinstance(r, APIRoute) for m in r.methods}

    assert routes == {
        ("GET", "/health"),
        ("GET", "/usage"),
        ("GET", "/incidents/{incident_id}/questions"),
        ("POST", "/incidents/{incident_id}/questions"),
    }