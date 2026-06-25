from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config_manager import ConfigManager
from core.logger import setup_logger


@dataclass(frozen=True)
class HexDumpConfig:
    """Hex dump configuration."""

    bytes_per_line: int
    offset_width: int
    max_lines: int


@dataclass(frozen=True)
class HexDumpSummary:
    """Summary statistics for a generated/exported hex dump."""

    filename: str
    filesize: int
    total_lines: int
    bytes_per_line: int
    truncated: bool
    export_path: Optional[Path]

    def to_dict(self) -> dict[str, Any]:
        """Convert summary to a JSON-serializable dict."""

        return {
            "filename": self.filename,
            "filesize": self.filesize,
            "total_lines": self.total_lines,
            "bytes_per_line": self.bytes_per_line,
            "truncated": self.truncated,
            "export_path": str(self.export_path) if self.export_path else None,
        }


class HexDumpViewer:
    """Generate, display, and save hex dumps for binary forensic workflows.

    Required methods are implemented:
    - validate_file
    - generate_dump
    - display_dump
    - save_dump
    - generate_summary

    The implementation is optimized for large files by streaming and
    limiting rendered/exported rows.
    """

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize the viewer.

        Args:
            console: Optional Rich Console.
        """

        self._console = console or Console()
        self._logger = setup_logger(name="rf_tools.hex_dump")
        self._config_manager = ConfigManager()

    @staticmethod
    def validate_file(file_path: Path) -> None:
        """Validate a file path.

        Args:
            file_path: Path to validate.

        Raises:
            FileNotFoundError: If the file does not exist.
            IsADirectoryError: If the path is a directory.
        """

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {file_path}")

    def _load_default_config(self) -> HexDumpConfig:
        """Load default hex dump settings from config/config.yaml."""

        bytes_per_line = self._config_manager.get(
            "hex_dump.bytes_per_line", 16
        )
        offset_width = self._config_manager.get("hex_dump.offset_width", 8)
        max_lines = self._config_manager.get("hex_dump.max_lines", 200)

        # Input validation (defensive; should already be valid from config).
        if int(bytes_per_line) <= 0:
            bytes_per_line = 16
        if int(offset_width) <= 0:
            offset_width = 8
        if int(max_lines) <= 0:
            max_lines = 200

        return HexDumpConfig(
            bytes_per_line=int(bytes_per_line),
            offset_width=int(offset_width),
            max_lines=int(max_lines),
        )

    @staticmethod
    def _to_ascii(chunk: bytes) -> str:
        out_chars: list[str] = []
        for b in chunk:
            if 32 <= b <= 126:
                out_chars.append(chr(b))
            else:
                out_chars.append(".")
        return "".join(out_chars)

    @staticmethod
    def _format_offset(offset: int, width: int) -> str:
        return f"{offset:0{width}x}"

    def generate_dump(
        self,
        file_path: Path,
        *,
        config: Optional[HexDumpConfig] = None,
        limit_lines: Optional[int] = None,
    ) -> tuple[Table, str, bool, int]:
        """Generate a Rich Table containing hex dump rows.

        Args:
            file_path: Target file.
            config: Optional explicit hex dump configuration.
            limit_lines: Optional override for maximum rendered lines.

        Returns:
            A tuple of (table, filename, truncated, total_lines).

        Raises:
            Exception: For any underlying I/O errors.
        """

        self.validate_file(file_path)
        target = file_path.expanduser().resolve()

        effective_config = config or self._load_default_config()
        if limit_lines is not None:
            if int(limit_lines) <= 0:
                raise ValueError("limit_lines must be > 0")
            effective_config = HexDumpConfig(
                bytes_per_line=effective_config.bytes_per_line,
                offset_width=effective_config.offset_width,
                max_lines=int(limit_lines),
            )

        total_size = target.stat().st_size
        bytes_per_line = effective_config.bytes_per_line

        # total lines is a theoretical value based on file size.
        total_lines = (total_size + bytes_per_line - 1) // bytes_per_line

        truncated = total_lines > effective_config.max_lines
        max_lines = min(total_lines, effective_config.max_lines)

        table = Table(box=None, show_lines=False)
        table.add_column("Offset", justify="right", style="bold magenta")
        table.add_column("Hex", style="bold")
        table.add_column("ASCII", style="green")

        try:
            with target.open("rb") as f:
                offset = 0
                for _ in range(max_lines):
                    chunk = f.read(bytes_per_line)
                    if not chunk:
                        break
                    hex_bytes = " ".join(f"{b:02x}" for b in chunk)
                    ascii_rep = self._to_ascii(chunk)
                    table.add_row(
                        self._format_offset(offset, effective_config.offset_width),
                        hex_bytes,
                        ascii_rep,
                    )
                    offset += len(chunk)
        except PermissionError as exc:
            raise PermissionError(f"Permission denied while reading: {target}") from exc
        except OSError as exc:
            raise OSError(f"Failed to read file for hex dump: {target}") from exc

        return table, target.name, truncated, total_lines

    def display_dump(
        self,
        file_path: Path,
        *,
        config: Optional[HexDumpConfig] = None,
        show_panel: bool = True,
        title: str = "Hex Dump",
    ) -> bool:
        """Display a hex dump.

        Args:
            file_path: Target file.
            config: Optional explicit configuration.
            show_panel: Whether to wrap the table in a Rich Panel.
            title: Panel title.

        Returns:
            True if the dump is truncated; otherwise False.
        """

        table, _filename, truncated, _total_lines = self.generate_dump(
            file_path, config=config
        )

        if show_panel:
            self._console.print(
                Panel(
                    table,
                    title=title,
                    border_style="cyan",
                    padding=(0, 1),
                )
            )
        else:
            self._console.print(table)

        return truncated

    @staticmethod
    def _safe_output_path(output_filename: str) -> Path:
        if not output_filename or output_filename.strip() == "":
            raise ValueError("output_filename must be non-empty")
        if Path(output_filename).name != output_filename:
            raise ValueError("output_filename must not contain directories")

        base_dir = Path("data/output").resolve()
        out_path = (base_dir / output_filename).resolve()
        if base_dir not in out_path.parents and out_path != base_dir:
            raise ValueError("Export path must be inside data/output/")
        return out_path

    def save_dump(
        self,
        file_path: Path,
        *,
        output_filename: str,
        config: Optional[HexDumpConfig] = None,
        export_lines: Optional[int] = None,
        include_summary_json: bool = True,
    ) -> HexDumpSummary:
        """Save a hex dump to data/output/.

        Args:
            file_path: Target file.
            output_filename: Output dump filename.
            config: Optional explicit configuration.
            export_lines: Optional override for maximum exported lines.
            include_summary_json: Whether to write a JSON summary next to dump.

        Returns:
            HexDumpSummary.
        """

        self.validate_file(file_path)
        target = file_path.expanduser().resolve()

        effective_config = config or self._load_default_config()
        if export_lines is not None:
            if int(export_lines) <= 0:
                raise ValueError("export_lines must be > 0")
            effective_config = HexDumpConfig(
                bytes_per_line=effective_config.bytes_per_line,
                offset_width=effective_config.offset_width,
                max_lines=int(export_lines),
            )

        out_path = self._safe_output_path(output_filename)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        total_size = target.stat().st_size
        bytes_per_line = effective_config.bytes_per_line
        total_lines = (total_size + bytes_per_line - 1) // bytes_per_line
        truncated = total_lines > effective_config.max_lines
        max_lines = min(total_lines, effective_config.max_lines)

        try:
            with target.open("rb") as fin, out_path.open(
                "w", encoding="utf-8", newline="\n"
            ) as fout:
                offset = 0
                lines_written = 0
                while lines_written < max_lines:
                    chunk = fin.read(bytes_per_line)
                    if not chunk:
                        break
                    hex_bytes = " ".join(f"{b:02x}" for b in chunk)
                    ascii_rep = self._to_ascii(chunk)
                    fout.write(
                        f"{self._format_offset(offset, effective_config.offset_width)}  "
                        f"{hex_bytes}  {ascii_rep}\n"
                    )
                    offset += len(chunk)
                    lines_written += 1
        except PermissionError as exc:
            raise PermissionError(f"Permission denied exporting dump for: {target}") from exc
        except OSError as exc:
            raise OSError(f"Failed to export hex dump to: {out_path}") from exc

        summary = self.generate_summary(
            filename=target.name,
            filesize=total_size,
            total_lines=total_lines,
            bytes_per_line=bytes_per_line,
            truncated=truncated,
            export_path=out_path,
        )

        if include_summary_json:
            summary_path = out_path.with_suffix(out_path.suffix + ".summary.json")
            try:
                summary_path.write_text(
                    json.dumps(summary.to_dict(), indent=2, sort_keys=True),
                    encoding="utf-8",
                )
            except OSError as exc:
                self._logger.warning(
                    "Failed to write hex dump summary JSON: %s", exc
                )

        return summary

    @staticmethod
    def generate_summary(
        filename: str,
        filesize: int,
        total_lines: int,
        bytes_per_line: int,
        truncated: bool,
        export_path: Optional[Path],
    ) -> HexDumpSummary:
        """Create a HexDumpSummary instance."""

        return HexDumpSummary(
            filename=filename,
            filesize=filesize,
            total_lines=total_lines,
            bytes_per_line=bytes_per_line,
            truncated=truncated,
            export_path=export_path,
        )

