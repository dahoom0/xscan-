"""
XScan EventBus
==============
Simple synchronous publish-subscribe bus.
Subscribers register a callable; events are dispatched synchronously.

Usage::

    from xscan.events import bus
    from xscan.schemas import EventType, DomainEvent

    bus.subscribe(EventType.FINDING_CREATED, handler)
    bus.publish(DomainEvent(type=EventType.FINDING_CREATED, scan_id="..."))
"""
from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Callable

from xscan.schemas.events import DomainEvent, EventType

logger = logging.getLogger(__name__)

Handler = Callable[[DomainEvent], None]


class EventBus:
    def __init__(self) -> None:
        self._handlers: dict[EventType, list[Handler]] = defaultdict(list)
        self._global: list[Handler] = []

    def subscribe(self, event_type: EventType, handler: Handler) -> None:
        """Register a handler for a specific event type."""
        self._handlers[event_type].append(handler)

    def subscribe_all(self, handler: Handler) -> None:
        """Register a handler that receives every event."""
        self._global.append(handler)

    def unsubscribe(self, event_type: EventType, handler: Handler) -> None:
        self._handlers[event_type] = [
            h for h in self._handlers[event_type] if h is not handler
        ]

    def publish(self, event: DomainEvent) -> None:
        """Dispatch event to all registered handlers (sync)."""
        for handler in self._handlers.get(event.type, []):
            try:
                handler(event)
            except Exception:
                logger.exception("EventBus handler error for %s", event.type)
        for handler in self._global:
            try:
                handler(event)
            except Exception:
                logger.exception("EventBus global handler error for %s", event.type)

    def clear(self) -> None:
        """Remove all handlers (useful in tests)."""
        self._handlers.clear()
        self._global.clear()


# Module-level singleton bus
bus = EventBus()
