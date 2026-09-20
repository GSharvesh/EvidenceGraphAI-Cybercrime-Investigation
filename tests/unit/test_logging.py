"""Unit tests for structlog structured logging."""

import logging

from core.logging.logger import configure_logging, get_logger


def test_configure_logging_console() -> None:
    """Verifies console logger configuration."""
    configure_logging(log_level="DEBUG", is_json=False)
    logger = get_logger("test.console")
    assert logger is not None
    root_logger = logging.getLogger()
    assert root_logger.level == logging.DEBUG


def test_configure_logging_json() -> None:
    """Verifies JSON logger configuration."""
    configure_logging(log_level="INFO", is_json=True)
    logger = get_logger("test.json")
    assert logger is not None
    root_logger = logging.getLogger()
    assert root_logger.level == logging.INFO


def test_get_logger_binding() -> None:
    """Verifies logger binding with logger name."""
    logger = get_logger("test.module")
    bound = logger.bind(correlation_id="test-uuid-1234")
    assert bound is not None
