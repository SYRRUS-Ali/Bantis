from __future__ import annotations

from abc import ABC, abstractmethod

from models import AnalysisTrace, CopilotRequest, CopilotResponse


class AIProvider(ABC):

    @abstractmethod
    def analyze_traced(self, request: CopilotRequest) -> AnalysisTrace:
        raise NotImplementedError

    def analyze(self, request: CopilotRequest) -> CopilotResponse:
        return self.analyze_traced(request).response