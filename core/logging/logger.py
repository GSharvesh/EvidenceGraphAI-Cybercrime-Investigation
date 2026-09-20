"""Structured logging setup using structlog."""

import logging
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor


def add_correlation_id(
    logger: Any, method_name: str, event_dict: EventDict
) -> EventDict:
    """Processor to ensure correlation_id is present in event dictionary."""
    if "correlation_id" not in event_dict:
        event_dict["correlation_id"] = None
    return event_dict


def configure_logging(log_level: str = "INFO", is_json: bool = False) -> None:
    """Configures structlog and standard logging handlers.

    Args:
        log_level: Desired log level string (e.g. DEBUG, INFO, WARNING, ERROR).
        is_json: If True, output structured JSON lines. If False, output colored console text.
    """
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    shared_processors: list[Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        add_correlation_id,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if is_json:
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors
        + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared_processors,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(numeric_level)


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Returns a structlog logger instance bound with logger name.

    Args:
        name: Name of the logger module.

    Returns:
        Configured structlog BoundLogger.
    """
    return structlog.get_logger(name)
