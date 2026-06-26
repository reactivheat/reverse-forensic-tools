from __future__ import annotations

import abc
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config_manager import ConfigManager
from core.logger import setup_logger


@dataclass(frozen=True)
class BinaryFileHashes:
    """Hashes commonly used for IOC correlation."""

    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert hashes to a JSON-serializable dict."""

        return {
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
        }


class BinaryParserBase(abc.ABC):
    """Abstract base class for all binary parsers.

    All reverse engineering parsers must inherit from this class and expose
    a stable interface.

    Implementers should:
      - store input file path
      - use validate() before parsing
      - parse() to populate internal state
      - display() / summary() / to_dict() for output
    """

    def __init__(
        self,
        file_path: Path,
        *,
        console: Optional[Console] = None,
        config: Optional[ConfigManager] = None,
    ) -> None:
        """Initialize the parser.

        Args:
            file_path: Path to the binary to parse.
            console: Optional Rich Console.
            config: Optional ConfigManager.
        """

        self._file_path = file_path
        self._console = console or Console()
        self._config = config or ConfigManager()
        self._logger = setup_logger(name=self.__class__.__name__)

        self._parsed: bool = False
        self._hashes: Optional[BinaryFileHashes] = None

    @property
    def file_path(self) -> Path:
        """Return the binary file path."""

        return self._file_path

    def validate(self) -> None:
        """Validate the input file.

        Raises:
            FileNotFoundError: If the file does not exist.
            IsADirectoryError: If the file_path is a directory.
            PermissionError: If the file cannot be read.
        """

        if not self._file_path.exists():
            raise FileNotFoundError(f"File not found: {self._file_path}")
        if not self._file_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {self._file_path}")

        # Permission check (best-effort, rely on open for authoritative check).
        try:
            with self._file_path.open("rb"):
                pass
        except PermissionError:
            raise
        except OSError as exc:
            # Keep message meaningful.
            raise OSError(f"Cannot read file: {self._file_path}") from exc

    @abc.abstractmethod
    def parse(self) -> None:
        """Parse the binary and populate internal structures."""

    @abc.abstractmethod
    def display(self) -> None:
        """Render a Rich representation of parsed results."""

    @abc.abstractmethod
    def summary(self) -> dict[str, Any]:
        """Return a dictionary summary of parsed results."""

    def to_dict(self) -> dict[str, Any]:
        """Alias for summary()."""

        return self.summary()

    def to_json(self) -> str:
        """Serialize summary() to a JSON string."""

        import json

        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def save_json(self, output_file: Path | str) -> Path:
        """Save the parsed summary as JSON under results/.

        Output restriction:
          - Must be located inside the project's `results/` directory.

        Args:
            output_file: Output filename or full path.

        Returns:
            The resolved output Path.

        Raises:
            ValueError: If output_file is outside results/.
            OSError: If writing fails.
        """

        out = Path(output_file)
        if out.is_absolute():
            out_resolved = out.resolve()
        else:
            out_resolved = (Path("results").resolve() / out).resolve()

        base_dir = Path("results").resolve()
        if base_dir not in out_resolved.parents and out_resolved != base_dir:
            raise ValueError("output_file must be inside results/")

        out_resolved.parent.mkdir(parents=True, exist_ok=True)

        # Ensure parse occurs before serialization.
        if not self._parsed:
            self.parse()
            self._parsed = True

        import json

        try:
            out_resolved.write_text(
                json.dumps(self.to_dict(), indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError as exc:
            self._logger.exception("Failed to write JSON output")
            raise OSError(f"Failed to write JSON output: {out_resolved}") from exc

        return out_resolved

    def _read_bytes(self, *, start: int = 0, length: Optional[int] = None) -> bytes:
        """Read bytes from the binary file.

        Args:
            start: Byte offset to start reading.
            length: Optional maximum number of bytes.

        Returns:
            The bytes read.

        Raises:
            ValueError: If start or length are invalid.
            OSError: If reading fails.
        """

        if start < 0:
            raise ValueError("start must be >= 0")
        if length is not None and length <= 0:
            raise ValueError("length must be > 0 when provided")

        try:
            with self._file_path.open("rb") as f:
                if start:
                    f.seek(start)
                if length is None:
                    return f.read()
                return f.read(length)
        except PermissionError:
            raise
        except OSError as exc:
            raise OSError(f"Failed to read bytes from: {self._file_path}") from exc

    def _get_size(self) -> int:
        """Get file size in bytes."""

        return self._file_path.stat().st_size

    def _compute_hashes(
        self,
        *,
        chunk_size: int = 1024 * 1024,
    ) -> BinaryFileHashes:
        """Compute MD5/SHA1/SHA256 hashes.

        Args:
            chunk_size: Streaming chunk size.

        Returns:
            BinaryFileHashes.

        Raises:
            ValueError: If chunk_size is invalid.
            PermissionError: If reading fails due to permissions.
            OSError: If file cannot be read.
        """

        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")

        md5_h = hashlib.md5()
        sha1_h = hashlib.sha1()
        sha256_h = hashlib.sha256()

        try:
            with self._file_path.open("rb") as f:
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    md5_h.update(chunk)
                    sha1_h.update(chunk)
                    sha256_h.update(chunk)
        except PermissionError:
            raise
        except OSError as exc:
            raise OSError(f"Failed to compute hashes for: {self._file_path}") from exc

        return BinaryFileHashes(
            md5=md5_h.hexdigest(),
            sha1=sha1_h.hexdigest(),
            sha256=sha256_h.hexdigest(),
        )

    def _ensure_hashes(self) -> BinaryFileHashes:
        """Ensure hashes are computed and cached."""

        if self._hashes is None:
            self._hashes = self._compute_hashes()
        return self._hashes

    def _render_default_summary_panel(
        self,
        title: str,
        rows: list[tuple[str, str]],
    ) -> Panel:
        """Render a default Rich panel for summary key/value rows."""

        table = Table(box=None, show_lines=False)
        table.add_column("Property", style="bold cyan")
        table.add_column("Value", style="white")
        for key, value in rows:
            table.add_row(key, value)

        return Panel(
            table,
            title=title,
            border_style="cyan",
            padding=(0, 1),
        )

    def _maybe_display_hashes(self) -> None:
        """Display a default Rich table of hashes."""

        hashes = self._ensure_hashes()
        panel = self._render_default_summary_panel(
            title="Hashes",
            rows=[
                ("MD5", hashes.md5 or ""),
                ("SHA1", hashes.sha1 or ""),
                ("SHA256", hashes.sha256 or ""),
            ],
        )
        self._console.print(panel)

    def _mark_parsed(self) -> None:
        """Internal helper to mark parse() as executed."""

        self._parsed = True

