import json
import subprocess
import sys
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .detection import UpstreamError

BRIDGE = Path(__file__).resolve().parents[2] / "response-controller" / "dashboard_review.py"


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    operation: Literal["approve", "modify", "dismiss"]
    action_id: str = Field(min_length=1, max_length=512)
    proposal_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    secret: str = Field(min_length=1, max_length=512, repr=False)
    reason: str = Field(default="", max_length=2000)
    params: dict = Field(default_factory=dict)


class ResponseController:
    def __init__(self, enabled: bool):
        self.enabled = enabled

    def request(self, incident_id: str, decision: Decision | None = None):
        if not self.enabled:
            raise UpstreamError(503, "Response review is not configured on this dashboard")
        payload = {"operation": "pending", "incident_id": incident_id}
        if decision:
            payload.update(decision.model_dump())
        try:
            encoded = json.dumps(payload, allow_nan=False)
        except (ValueError, RecursionError) as exc:
            raise UpstreamError(422, "Review parameters must contain valid JSON values") from exc
        if len(encoded.encode()) > 16_384:
            raise UpstreamError(422, "Review request exceeds the size limit")
        try:
            result = subprocess.run(
                [sys.executable, str(BRIDGE)], input=encoded, text=True,
                capture_output=True, timeout=120, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise UpstreamError(503, "Controller unavailable. Refresh proposals and audit log before retrying; delivery is uncertain") from exc
        if result.returncode or len(result.stdout) > 2_000_000:
            raise UpstreamError(503, "Controller failed. Refresh proposals and audit log before retrying")
        try:
            data = json.loads(result.stdout)
            if not isinstance(data, dict):
                raise ValueError("Expected object")
        except ValueError as exc:
            raise UpstreamError(502, "Controller returned invalid data") from exc
        if "error" in data:
            raise UpstreamError(data["code"], data["error"])
        return data