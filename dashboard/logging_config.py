"""
Structured JSON logging via structlog.

Call configure_logging() once at application startup (app.py does this).
All other modules should import get_logger and call it at module level.
"""

from __future__ import annotations

import logging
import os
import sys

import structlog


def configure_logging() -> None:
    """Configure structlog + stdlib logging for the process.

    Outputs JSON in production (LOG_FORMAT=json or when not a TTY).
    Outputs human-friendly coloured output in development.
    """
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    json_mode = os.getenv("LOG_FORMAT", "").lower() == "json" or not sys.stderr.isatty()

    shared_processors: list = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_mode:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, log_level, logging.INFO))


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a structlog logger bound to *name*."""
    return structlog.get_logger(name)
