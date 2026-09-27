"""Exceptions for the EvidenceGraphAI events subsystem."""


class EventError(Exception):
    """Base exception for all event-related errors."""


class EventBusError(EventError):
    """Exception raised when event bus operations fail."""


class EventPublishError(EventError):
    """Exception raised when an event cannot be published."""
