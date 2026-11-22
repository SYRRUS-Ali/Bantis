import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.skipif(shutil.which("docker") is None, reason="Docker Compose CLI is not installed")
def test_compose_dependency_graph_and_host_boundaries():
    result = subprocess.run(["docker", "compose", "--env-file", "/dev/null", "-f", str(ROOT / "compose.yaml"),
                             "--profile", "range", "--profile", "ai", "config", "--format", "json"],
                            env={"PATH": os.environ["PATH"], "HOME": os.environ.get("HOME", "")},
                            capture_output=True, text=True, timeout=20, check=True)
    services = json.loads(result.stdout)["services"]
    assert set(services) == {"detection-engine", "copilot-api", "copilot-worker", "api", "db", "redis", "nginx"}
    for name, service in services.items():
        for port in service.get("ports", []):
            assert port["host_ip"] == "127.0.0.1"
        assert service["logging"]["options"] == {"max-size": "10m", "max-file": "3"}
        assert not any("docker.sock" in str(volume) for volume in service.get("volumes", []))
        for dependency in service.get("depends_on", {}).values():
            assert dependency["condition"] == "service_healthy"
        if name != "copilot-worker":
            assert service["healthcheck"]["test"]
    for name in ("copilot-api", "copilot-worker"):
        mounts = {volume["target"]: volume for volume in services[name]["volumes"]}
        assert mounts["/run/bantis"]["read_only"] is True
        assert mounts["/run/bantis-key"]["read_only"] is True
        assert services[name]["user"] == "1000:1000"
        assert "COPILOT_API_TOKEN" not in services[name]["environment"]
        assert services[name]["environment"]["BANTIS_COPILOT_TOKEN_CONFIG"] == "/run/bantis/orchestration.json"
    detection = services["detection-engine"]
    detection_mounts = {volume["target"]: volume for volume in detection["volumes"]}
    assert detection_mounts["/run/bantis"]["read_only"] is True
    assert detection_mounts["/run/bantis-key"]["read_only"] is True
    assert detection["environment"]["BANTIS_ORCHESTRATION_STATE"] == "/run/bantis"
    assert detection["environment"]["BANTIS_SECRETS_KEY_FILE"].startswith("/run/bantis-key/")