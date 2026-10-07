from __future__ import annotations

from abc import ABC, abstractmethod

from models import CopilotRequest, CopilotResponse


class AIProvider(ABC):

    @abstractmethod
    def analyze(self, request: CopilotRequest) -> CopilotResponse:
        raise NotImplementedError