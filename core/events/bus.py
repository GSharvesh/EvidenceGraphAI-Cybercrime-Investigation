"""In-process asynchronous event bus supporting multi-subscriber pub/sub."""

import asyncio
from collections.abc import AsyncIterator, Sequence

from core.events.types import Event
from core.logging.logger import get_logger

logger = get_logger("core.events.bus")


class EventBus:
    """In-process asynchronous event bus with bounded queues per subscriber."""

    def __init__(self) -> None:
        # Mapping from event_type (or None for all) to a set of subscriber queues
        self._subscribers: dict[str | None, set[asyncio.Queue[Event]]] = {None: set()}

    def subscribe_queue(
        self,
        event_type: str | Sequence[str] | set[str] | None = None,
        maxsize: int = 100,
    ) -> asyncio.Queue[Event]:
        """Creates and registers a new subscriber queue.

        Args:
            event_type: Specific event_type (or collection of types), or None for all events.
            maxsize: Maximum queue capacity before dropping oldest events.

        Returns:
            An asyncio.Queue instance receiving published events.
        """
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        types_to_register: set[str | None]
        if isinstance(event_type, str) or event_type is None:
            types_to_register = {event_type}
        else:
            types_to_register = set(event_type)

        for et in types_to_register:
            if et not in self._subscribers:
                self._subscribers[et] = set()
            self._subscribers[et].add(queue)

        logger.debug(
            "Subscriber registered",
            event_type=str(event_type),
            total_queues=self.total_subscribers,
        )
        return queue

    def unsubscribe_queue(
        self,
        queue: asyncio.Queue[Event],
        event_type: str | Sequence[str] | set[str] | None = None,
    ) -> None:
        """Unregisters an active subscriber queue.

        Args:
            queue: The subscriber queue to remove.
            event_type: The event type(s) it was registered with.
        """
        types_to_remove: set[str | None]
        if isinstance(event_type, str) or event_type is None:
            types_to_remove = {event_type}
        else:
            types_to_remove = set(event_type)

        for et in types_to_remove:
            if et in self._subscribers:
                self._subscribers[et].discard(queue)
                if not self._subscribers[et] and et is not None:
                    del self._subscribers[et]

        logger.debug("Subscriber unregistered", event_type=str(event_type))

    async def subscribe(
        self, event_type: str | None = None, maxsize: int = 100
    ) -> AsyncIterator[Event]:
        """Asynchronous iterator for consuming events of an optional type.

        Args:
            event_type: Specific event_type to listen to, or None for all events.
            maxsize: Maximum queue capacity.

        Yields:
            Event instances as they are published.
        """
        queue = self.subscribe_queue(event_type=event_type, maxsize=maxsize)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            self.unsubscribe_queue(queue, event_type=event_type)

    def publish(self, event: Event) -> None:
        """Publishes an event to all matching registered subscriber queues.

        Drops the oldest event if a subscriber queue is full to prevent blocking.

        Args:
            event: Event instance to broadcast.
        """
        target_queues: set[asyncio.Queue[Event]] = set()

        # Wildcard subscribers (listening to all events)
        if None in self._subscribers:
            target_queues.update(self._subscribers[None])

        # Specific event type subscribers
        if event.event_type in self._subscribers:
            target_queues.update(self._subscribers[event.event_type])

        if not target_queues:
            return

        for q in target_queues:
            if q.full():
                try:
                    dropped = q.get_nowait()
                    logger.warning(
                        "Subscriber queue full; dropped oldest event",
                        dropped_event_id=dropped.event_id,
                        event_type=dropped.event_type,
                    )
                except asyncio.QueueEmpty:
                    pass
            try:
                q.put_nowait(event)
            except Exception as exc:
                logger.warning(
                    "Failed to deliver event to subscriber",
                    error=str(exc),
                    event_id=event.event_id,
                )

    @property
    def total_subscribers(self) -> int:
        """Returns the total number of active subscriber queues across all event types."""
        return sum(len(queues) for queues in self._subscribers.values())


# Global singleton instance
_GLOBAL_BUS: EventBus | None = None


def get_event_bus() -> EventBus:
    """Returns the process-wide EventBus singleton."""
    global _GLOBAL_BUS
    if _GLOBAL_BUS is None:
        _GLOBAL_BUS = EventBus()
    return _GLOBAL_BUS


def reset_event_bus() -> None:
    """Resets the singleton event bus (primarily for test isolation)."""
    global _GLOBAL_BUS
    _GLOBAL_BUS = None
