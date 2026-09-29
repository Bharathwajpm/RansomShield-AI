"""
RansomShield AI — Structured Backend Logger
Phase 3A: Backend Foundation

Provides standardized structured logging for backend lifecycle events, HTTP requests,
and domain operations.
"""

import logging
import sys
from typing import Optional


class BackendLogger:
    """
    Standardized logger setup for the RansomShield FastAPI backend.
    """

    @classmethod
    def get_logger(cls, name: str = "RansomShieldBackend", level: str = "INFO") -> logging.Logger:
        logger = logging.getLogger(name)
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))

        if not logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)

        return logger
