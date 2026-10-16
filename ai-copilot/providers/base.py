from __future__ import annotations

from abc import ABC, abstractmethod

from models import AnalysisTrace, CopilotRequest, CopilotResponse, FollowupTrace


class ProviderUnavailableError(RuntimeError):
    """The provider could not be reached or refused service (network,
    timeout, overload, rate limit, missing or rejected key) before any
    answer came back. Nothing was decided about the incident, so callers
    must not record this as its analysis: a later call can succeed.
    """


class AIProvider(ABC):

    @abstractmethod
    def analyze_traced(self, request: CopilotRequest) -> AnalysisTrace:
        raise NotImplementedError

    def analyze(self, request: CopilotRequest) -> CopilotResponse:
        return self.analyze_traced(request).response

    def ask(
        self,
        request: CopilotRequest,
        analysis: CopilotResponse,
        history: list[tuple[str, str]],
        question: str,
    ) -> FollowupTrace:
        raise NotImplementedError(f"{type(self).__name__} does not support follow-up questions")


class UnavailableProvider(AIProvider):
    """Stands in when no provider can be configured, so the worker and API
    still start and incidents still flow -- just without AI analysis.
    """

    model = "none"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def analyze_traced(self, request: CopilotRequest) -> AnalysisTrace:
        raise ProviderUnavailableError(self.reason)

    def ask(self, request, analysis, history, question) -> FollowupTrace:
        raise ProviderUnavailableError(self.reason)