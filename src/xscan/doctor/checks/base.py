"""Base class for all doctor checks."""
from __future__ import annotations
from abc import ABC, abstractmethod
from xscan.services.doctor import HealthResult


class BaseCheck(ABC):
    name: str = "unnamed"

    @abstractmethod
    def run(self) -> HealthResult: ...

    def fix(self) -> None:
        """Override to implement automatic repair."""
