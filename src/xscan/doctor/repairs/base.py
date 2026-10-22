"""
RepairBase — contract for all repair recipes.

Rules:
  - Each repair has explicit preconditions, steps, and verification.
  - Repairs execute through the runtime abstraction (never raw subprocess).
  - LLM may propose a repair recipe but CANNOT execute it directly.
  - Repairs require explicit user approval when permission_required=True.
"""
from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class RepairResult:
    name: str
    success: bool
    detail: str = ""
    steps_completed: list[str] = field(default_factory=list)


class RepairBase(ABC):
    name: str = "unnamed-repair"
    description: str = ""
    permission_required: bool = False   # True = ask user before executing

    @abstractmethod
    def check_preconditions(self) -> bool:
        """Return True if this repair is applicable right now."""
        ...

    @abstractmethod
    def execute(self) -> RepairResult:
        """Run the repair. Must not execute LLM-generated shell commands."""
        ...

    def verify(self) -> bool:
        """Verify the repair succeeded. Override for post-repair checks."""
        return True
