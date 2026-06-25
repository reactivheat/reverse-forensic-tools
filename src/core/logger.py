from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.logging import RichHandler

from core.config_manager import ConfigManager


@dataclass(frozen=True)
class LoggerPaths:
    """Resolved logger file paths."""

    log_dir: Path
    log_file: Path


class LoggerManager:
    """Thread-safe singleton logger manager for the project."""

    _instance: "LoggerManager | None" = None
    _lock = threading.Lock()

    def __new__(cls, *args: object, **kwargs: object) -> "LoggerManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        if hasattr(self, "_initialized") and getattr(self, "_initialized"):
            return

        self._config = ConfigManager()
        self._console = Console()
        self._configured = False
        self._initialized = True

    def get_logger(self, name: str = "rf_tools") -> logging.Logger:
        """Return a configured logger for the given name."""

        self.configure()
        return logging.getLogger(name)

    def configure(self) -> None:
        """Configure root handlers once to prevent duplicate handlers."""

        with self._lock:
            if self._configured:
                return

            level_str = self._config.get("logging.level", "INFO")
            level = self._coerce_log_level(level_str)

            root = logging.getLogger()
            root.setLevel(level)

            # Prevent duplicate handlers.
            existing_handler_types = {type(h) for h in root.handlers}

            formatter = logging.Formatter(
                fmt="%(asctime)s\n%(levelname)s\n%(name)s\n%(message)s"
            )

            if RichHandler not in existing_handler_types:
                console_handler = self.create_console_handler(level=level)
                console_handler.setFormatter(formatter)
                root.addHandler(console_handler)

            file_handler = self.create_file_handler(level=level)
            if RotatingFileHandler not in existing_handler_types:
                file_handler.setFormatter(formatter)
                root.addHandler(file_handler)

            self._configured = True

    @staticmethod
    def _coerce_log_level(level: object) -> int:
        level_s = str(level).strip().upper()
        if not level_s:
            return logging.INFO
        if level_s.isdigit():
            return int(level_s)
        return getattr(logging, level_s, logging.INFO)

    def _resolve_paths(self) -> LoggerPaths:
        log_dir = Path("logs").resolve()
        log_file = log_dir / "reverse_forensic_tools.log"
        return LoggerPaths(log_dir=log_dir, log_file=log_file)

    def create_console_handler(self, level: int) -> RichHandler:
        """Create a Rich console handler."""

        return RichHandler(
            rich_tracebacks=True,
            console=self._console,
            show_time=True,
            show_level=True,
            show_path=False,
            level=level,
        )

    def create_file_handler(self, level: int) -> RotatingFileHandler:
        """Create a rotating file handler."""

        paths = self._resolve_paths()
        paths.log_dir.mkdir(parents=True, exist_ok=True)

        # 5MB per file, keep up to 3 backups.
        return RotatingFileHandler(
            filename=str(paths.log_file),
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
            delay=True,
            level=level,
        )


def setup_logger(name: str = "rf_tools") -> logging.Logger:
    """Project-wide logger setup.

    This function keeps the public API stable. Internally it delegates to
    LoggerManager.

    Args:
        name: Logger name.

    Returns:
        Configured logger instance.
    """

    manager = LoggerManager()
    return manager.get_logger(name=name)

