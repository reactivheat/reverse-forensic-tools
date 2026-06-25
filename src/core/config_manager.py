from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import yaml
from rich.console import Console
from rich.panel import Panel


@dataclass(frozen=True)
class ConfigPaths:
    """Resolved configuration paths."""

    config_file: Path


class ConfigManager:
    """Thread-safe singleton configuration manager for YAML.

    Loads configuration from config/config.yaml and provides nested key
    access using dot-separated paths.
    """

    _instance: Optional["ConfigManager"] = None
    _lock = threading.Lock()

    def __new__(cls, *args: Any, **kwargs: Any) -> "ConfigManager":
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, config_path: str | Path = "config/config.yaml") -> None:
        """Initialize ConfigManager.

        Args:
            config_path: Path to YAML configuration.
        """

        if hasattr(self, "_initialized") and self._initialized:  # type: ignore[attr-defined]
            return

        self._console = Console()
        self._config_file = Path(config_path).expanduser().resolve()
        self._paths = ConfigPaths(config_file=self._config_file)
        self._config: dict[str, Any] = {}

        self.load()
        self._initialized = True  # type: ignore[attr-defined]

    def _default_yaml(self) -> str:
        return (
            "application:\n"
            "  name: Reverse Forensic Tools\n"
            "  author: Efraim Wattimury\n"
            "  brand: Operator Cedra\n"
            "\n"
            "logging:\n"
            "  level: INFO\n"
            "\n"
            "hex_dump:\n"
            "  bytes_per_line: 16\n"
            "  offset_width: 8\n"
            "  max_lines: 200\n"
        )

    def _ensure_config_file(self) -> None:
        if self._config_file.exists():
            return
        self._config_file.parent.mkdir(parents=True, exist_ok=True)
        self._config_file.write_text(self._default_yaml(), encoding="utf-8")

    @staticmethod
    def _split_key(key: str) -> list[str]:
        if not key or not key.strip():
            raise ValueError("Config key must be a non-empty string")
        return [part for part in key.split(".") if part]

    @staticmethod
    def _is_mapping(value: Any) -> bool:
        return isinstance(value, dict)

    def validate(self, config: dict[str, Any]) -> None:
        """Validate configuration structure.

        Currently performs defensive validation for expected keys.

        Args:
            config: Parsed YAML config.

        Raises:
            ValueError: If configuration is structurally invalid.
        """

        if not isinstance(config, dict):
            raise ValueError("Configuration root must be a mapping")

        # hex_dump must be present as a mapping when used; create if missing.
        hex_dump = config.get("hex_dump")
        if hex_dump is None:
            config["hex_dump"] = {}
            return

        if not self._is_mapping(hex_dump):
            raise ValueError("hex_dump must be a mapping")

    def load(self) -> None:
        """Load configuration from disk, creating defaults if missing."""

        self._ensure_config_file()
        try:
            raw = self._config_file.read_text(encoding="utf-8")
            parsed = yaml.safe_load(raw) or {}
            if not isinstance(parsed, dict):
                raise ValueError("config/config.yaml root must be a mapping")
            self.validate(parsed)
            self._config = parsed
        except FileNotFoundError:
            self._config = {}
        except yaml.YAMLError as exc:
            self._console.print(
                Panel(
                    f"[bold red]YAML error[/bold red]: {exc}\nFile: {self._config_file}",
                    title="ConfigManager",
                    border_style="red",
                )
            )
            raise
        except Exception as exc:
            self._console.print(
                Panel(
                    f"[bold red]Failed to load config[/bold red]: {exc}\nFile: {self._config_file}",
                    title="ConfigManager",
                    border_style="red",
                )
            )
            raise

    def reload(self) -> None:
        """Reload configuration from disk."""

        with self._lock:
            self.load()

    def save(self) -> None:
        """Save current configuration back to config/config.yaml."""

        try:
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            text = yaml.safe_dump(self._config, sort_keys=False)
            self._config_file.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise OSError(f"Failed to save config: {self._config_file}") from exc

    def has_key(self, key: str) -> bool:
        """Check if a nested key exists."""

        try:
            parts = self._split_key(key)
        except ValueError:
            return False

        current: Any = self._config
        for part in parts:
            if not self._is_mapping(current):
                return False
            if part not in current:
                return False
            current = current[part]
        return True

    def get(self, key: str, default: Any = None) -> Any:
        """Get a nested configuration value.

        Args:
            key: Dot-separated key (e.g., "hex_dump.bytes_per_line").
            default: Value to return when the key does not exist.

        Returns:
            The configuration value or default.
        """

        parts = self._split_key(key)
        current: Any = self._config
        for part in parts:
            if not self._is_mapping(current) or part not in current:
                return default
            current = current[part]
        return current

    def set(self, key: str, value: Any) -> None:
        """Set a nested configuration value, creating intermediate maps."""

        parts = self._split_key(key)
        current: Any = self._config
        for part in parts[:-1]:
            if not self._is_mapping(current):
                raise ValueError(f"Cannot set nested key under non-mapping at: {part}")
            if part not in current or not self._is_mapping(current[part]):
                current[part] = {}
            current = current[part]

        last = parts[-1]
        if not self._is_mapping(current):
            raise ValueError("Invalid configuration structure")
        current[last] = value

    def __repr__(self) -> str:
        return f"ConfigManager(config_file={self._paths.config_file!s})"

