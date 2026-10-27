from __future__ import annotations

import os

from actions.promotion_hold import HoldPromotion, LiftPromotionHold
from github_client import DEFAULT_API_URL, GitHubVariables
from registry import ActionRegistry


def promotion_client(env: dict[str, str] | None = None) -> GitHubVariables | None:
    env = os.environ if env is None else env
    repo = env.get("RESPONSE_GITHUB_REPO", "")
    token = env.get("RESPONSE_GITHUB_TOKEN_PROMOTION", "")
    if not repo or not token:
        return None
    return GitHubVariables(repo, token, env.get("RESPONSE_GITHUB_API_URL") or DEFAULT_API_URL)


def build_registry(env: dict[str, str] | None = None) -> ActionRegistry:
    registry = ActionRegistry()
    client = promotion_client(env)
    registry.register(HoldPromotion(client))
    registry.register(LiftPromotionHold(client))
    return registry