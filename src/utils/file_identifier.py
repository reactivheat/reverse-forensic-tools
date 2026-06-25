from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import magic
from rich.console import Console
from rich.table import Table


@dataclass(frozen=True)
class FileIdentification:
    """Holds file identification results."""

    path: Path
    size_bytes: int
    mime_type: Optional[str]
    description: Optional[str]
    magic_bytes: Optional[str]


class FileIdentifier:
    """Identify file type using libmagic and basic magic bytes.

    Notes:
        - Requires the optional dependency `python-magic`.
        - On Linux, ensure libmagic is installed.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize FileIdentifier.

        Args:
            console: Optional Rich console for pretty printing.
        """

        self._console = console or Console()
        # python-magic's Magic is relatively expensive; instantiate once.
        # mime=True returns a MIME type when available.
        try:
            self._magic_mime = magic.Magic(mime=True)
            self._magic_desc = magic.Magic(mime=False)
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Failed to initialize libmagic (python-magic). "
                "Ensure libmagic is installed on the system."
            ) from exc

    @staticmethod
    def _validate_file(file_path: Path) -> None:
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {file_path}")

    @staticmethod
    def _extract_magic_bytes(file_path: Path, n: int = 16) -> str:
        """Extract the first n bytes and return as hex string."""

        if n <= 0:
            return ""
        with file_path.open("rb") as f:
            b = f.read(n)
        return b.hex()

    def identify(
        self,
        file_path: Path,
        show_table: bool = True,
        magic_bytes_preview: int = 16,
    ) -> FileIdentification:
        """Identify a file.

        Args:
            file_path: Target file.
            show_table: If True, render a Rich table.
            magic_bytes_preview: Number of bytes to preview from start of file.

        Returns:
            FileIdentification results.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            IsADirectoryError: If path is a directory.
            PermissionError: If file can't be accessed.
            RuntimeError: If libmagic fails.
        """

        target = file_path.expanduser().resolve()
        self._validate_file(target)

        try:
            size_bytes = target.stat().st_size
            magic_bytes = self._extract_magic_bytes(target, magic_bytes_preview)

            mime_type = None
            description = None
            try:
                mime_type = self._magic_mime.from_file(str(target))
            except Exception:
                # Keep going; mime_type is best-effort.
                mime_type = None

            try:
                description = self._magic_desc.from_file(str(target))
            except Exception:
                description = None

        except PermissionError as exc:
            raise PermissionError(f"Permission denied while reading: {target}") from exc
        except OSError as exc:
            raise OSError(f"Failed to read file for identification: {target}") from exc
        except Exception as exc:
            raise RuntimeError(f"File identification failed for: {target}") from exc

        result = FileIdentification(
            path=target,
            size_bytes=size_bytes,
            mime_type=mime_type,
            description=description,
            magic_bytes=magic_bytes if magic_bytes else None,
        )

        if show_table:
            table = Table(title="File Identification", box=None)
            table.add_column("Field", style="bold cyan")
            table.add_column("Value", style="white")
            table.add_row("Path", str(result.path))
            table.add_row("Size", str(result.size_bytes))
            table.add_row("MIME", result.mime_type or "unknown")
            table.add_row("Description", result.description or "unknown")
            table.add_row("Magic Bytes", result.magic_bytes or "unknown")
            self._console.print(table)

        return result

    @staticmethod
    def to_dict(result: FileIdentification) -> dict[str, Any]:
        """Convert FileIdentification to a JSON-serializable dict."""

        return {
            "path": str(result.path),
            "size_bytes": result.size_bytes,
            "mime_type": result.mime_type,
            "description": result.description,
            "magic_bytes": result.magic_bytes,
        }

