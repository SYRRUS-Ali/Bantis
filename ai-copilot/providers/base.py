from __future__ import annotations

from abc import ABC, abstractmethod

from models import AnalysisTrace, CopilotRequest, CopilotResponse, FollowupTrace


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