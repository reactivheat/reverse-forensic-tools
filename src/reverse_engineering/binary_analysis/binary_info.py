from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config_manager import ConfigManager
from core.logger import setup_logger
from reverse_engineering.binary_analysis.base_parser import BinaryParserBase
from reverse_engineering.binary_analysis.binary_detector import BinaryDetector
from reverse_engineering.binary_analysis.import_parser import ImportParser
from reverse_engineering.binary_analysis.pe_parser import PEParser
from reverse_engineering.binary_analysis.section_parser import SectionParser


@dataclass(frozen=True)
class AnalysisResult:
    """Container for combined binary analysis output."""

    file_path: Path
    detected_type: str
    confidence: float
    per_parser: dict[str, dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""

        return {
            "file_path": str(self.file_path),
            "detected_type": self.detected_type,
            "confidence": self.confidence,
            "per_parser": self.per_parser,
        }


class BinaryInfo:
    """High-level orchestrator that analyzes binaries.

    This module detects executable format and dispatches to the appropriate
    parser(s) for the detected type.

    Currently implemented:
      - PE: PEParser + SectionParser + ImportParser
      - Others: detection only (extend with ELF/Mach-O parsers later)
    """

    def __init__(
        self,
        file_path: Path,
        *,
        console: Optional[Console] = None,
        config: Optional[ConfigManager] = None,
    ) -> None:
        """Initialize BinaryInfo.

        Args:
            file_path: Path to the binary to analyze.
            console: Optional Rich console.
            config: Optional ConfigManager.
        """

        self._file_path = file_path
        self._console = console or Console()
        self._config = config or ConfigManager()
        self._logger = setup_logger(name="rf_tools.binary_info")

        self._detector = BinaryDetector()
        self._result: Optional[AnalysisResult] = None

        self._parsers: list[BinaryParserBase] = []

    @property
    def file_path(self) -> Path:
        """Return file path."""

        return self._file_path

    def analyze(self) -> AnalysisResult:
        """Analyze the file and return a combined result.

        Returns:
            AnalysisResult with per-parser outputs.
        """

        if not self._file_path.exists():
            raise FileNotFoundError(f"File not found: {self._file_path}")
        if not self._file_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {self._file_path}")

        detected = self._detector.detect(self._file_path)

        detected_type = detected.kind
        confidence = detected.confidence

        per_parser: dict[str, dict[str, Any]] = {}
        self._parsers = []

        try:
            if detected_type == "PE":
                pe_parser = PEParser(self._file_path, console=self._console, config=self._config)
                sec_parser = SectionParser(
                    self._file_path, console=self._console, config=self._config
                )
                imp_parser = ImportParser(
                    self._file_path, console=self._console, config=self._config
                )

                self._parsers = [pe_parser, sec_parser, imp_parser]

                for parser in self._parsers:
                    parser.validate()
                    parser.parse()
                    per_parser[parser.__class__.__name__] = parser.summary()

            else:
                # Not implemented yet; keep detection-only output.
                per_parser = {}

        except Exception as exc:
            self._logger.exception("Binary analysis failed")
            raise exc

        self._result = AnalysisResult(
            file_path=self._file_path.expanduser().resolve(),
            detected_type=detected_type,
            confidence=confidence,
            per_parser=per_parser,
        )
        return self._result

    def display(self) -> None:
        """Display analysis results using Rich."""

        if self._result is None:
            self.analyze()

        assert self._result is not None
        res = self._result

        table = Table(box=None, show_lines=False)
        table.add_column("Field", style="bold cyan")
        table.add_column("Value", style="white")
        table.add_row("File", str(res.file_path))
        table.add_row("Detected Type", res.detected_type)
        table.add_row("Confidence", f"{res.confidence:.2f}")

        self._console.print(
            Panel(table, title="Binary Detection", border_style="cyan", padding=(0, 1))
        )

        for parser_name, parser_summary in res.per_parser.items():
            summary_table = Table(box=None, show_lines=False)
            summary_table.add_column("Key", style="bold cyan")
            summary_table.add_column("Value", style="white")
            for k, v in list(parser_summary.items())[:25]:
                summary_table.add_row(str(k), str(v))

            self._console.print(
                Panel(
                    summary_table,
                    title=f"Summary: {parser_name}",
                    border_style="cyan",
                    padding=(0, 1),
                )
            )

    def summary(self) -> dict[str, Any]:
        """Return combined analysis summary."""

        if self._result is None:
            self.analyze()
        assert self._result is not None
        return self._result.to_dict()

    def save_json(self, output_file: Path | str) -> Path:
        """Save combined analysis JSON inside results/."""

        import json

        out = Path(output_file)
        if out.is_absolute():
            out_resolved = out.resolve()
        else:
            out_resolved = (Path("results").resolve() / out).resolve()

        base_dir = Path("results").resolve()
        if base_dir not in out_resolved.parents and out_resolved != base_dir:
            raise ValueError("output_file must be inside results/")

        out_resolved.parent.mkdir(parents=True, exist_ok=True)

        data = self.summary()
        try:
            out_resolved.write_text(
                json.dumps(data, indent=2, sort_keys=True), encoding="utf-8"
            )
        except OSError as exc:
            self._logger.exception("Failed to save JSON")
            raise OSError(f"Failed to save JSON to: {out_resolved}") from exc

        return out_resolved

