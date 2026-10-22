"""
Replay specification — defines how a finding can be replicated.

A ReplaySpec captures everything needed to reproduce a finding:
  - The exact HTTP request
  - The expected observable behaviour
  - Steps to confirm in a browser

This is separate from evidence capture — it is produced by the
validation node after a finding is confirmed.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class ReplayStep:
    description: str
    request_method: str = "GET"
    request_url: str = ""
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    expected_indicator: str = ""   # what to look for in the response


@dataclass
class ReplaySpec:
    finding_id: str
    scan_id: str
    title: str
    steps: list[ReplayStep] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "scan_id":    self.scan_id,
            "title":      self.title,
            "steps": [
                {
                    "description":        s.description,
                    "request_method":     s.request_method,
                    "request_url":        s.request_url,
                    "expected_indicator": s.expected_indicator,
                }
                for s in self.steps
            ],
            "notes": self.notes,
        }
