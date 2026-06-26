from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pefile
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config_manager import ConfigManager
from reverse_engineering.binary_analysis.base_parser import BinaryParserBase


@dataclass(frozen=True)
class ImportEntry:
    """Represent a single imported function."""

    dll: str
    api: str
    ordinal: Optional[int]
    hint: Optional[int]
    delay_import: bool
    suspicious: bool

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "dll": self.dll,
            "api": self.api,
            "ordinal": self.ordinal,
            "hint": self.hint,
            "delay_import": self.delay_import,
            "suspicious": self.suspicious,
        }


class ImportParser(BinaryParserBase):
    """Parse PE import tables and flag suspicious APIs."""

    DEFAULT_SUSPICIOUS_APIS: tuple[str, ...] = (
        "CreateRemoteThread",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "LoadLibraryA",
        "GetProcAddress",
        "WinExec",
        "ShellExecute",
        "URLDownloadToFile",
        "InternetOpen",
        "InternetReadFile",
    )

    def __init__(
        self,
        file_path: Path,
        *,
        console: Optional[Console] = None,
        config: Optional[ConfigManager] = None,
    ) -> None:
        """Initialize ImportParser."""

        super().__init__(file_path, console=console, config=config)
        self._pe: Optional[pefile.PE] = None
        self._imports: list[ImportEntry] = []
        self._suspicious_set: set[str] = set(
            api.lower() for api in self.DEFAULT_SUSPICIOUS_APIS
        )

    def validate(self) -> None:
        """Validate that the input is a PE file."""

        super().validate()
        try:
            pefile.PE(str(self.file_path), fast_load=True)
        except pefile.PEFormatError as exc:
            raise ValueError(f"Not a valid PE file: {self.file_path}") from exc

    def parse(self) -> None:
        """Parse imports (normal and delay imports) for the PE file."""

        self.validate()

        try:
            self._pe = pefile.PE(str(self.file_path), fast_load=False)
        except Exception as exc:
            raise OSError(f"Failed to load PE imports: {self.file_path}") from exc

        assert self._pe is not None
        pe = self._pe

        self._imports = []
        entropy_threshold = None
        _ = entropy_threshold

        # Delay imports directory may not exist.
        delay_exists = False
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
                delay_exists = True
        except Exception:
            delay_exists = False

        # Regular imports.
        try:
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = getattr(entry, "dll", b"")
                    dll = dll_name.decode(errors="replace") if isinstance(dll_name, bytes) else str(dll_name)
                    # Each import has .imports list with imported symbols
                    for imp in getattr(entry, "imports", []) or []:
                        name = getattr(imp, "name", None)
                        api = name.decode(errors="replace") if isinstance(name, bytes) else (str(name) if name is not None else "unknown")
                        ordinal_raw = getattr(imp, "ordinal", None)
                        hint_raw = getattr(imp, "hint", None)
                        ordinal = int(ordinal_raw) if ordinal_raw is not None else None
                        hint = int(hint_raw) if hint_raw is not None else None
                        suspicious = api.lower() in self._suspicious_set

                        self._imports.append(
                            ImportEntry(
                                dll=dll,
                                api=api,
                                ordinal=ordinal,
                                hint=hint,
                                delay_import=False,
                                suspicious=suspicious,
                            )
                        )
        except Exception:
            # best-effort parsing
            pass

        # Delay imports.
        try:
            if delay_exists:
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    dll_name = getattr(entry, "dll", b"")
                    dll = dll_name.decode(errors="replace") if isinstance(dll_name, bytes) else str(dll_name)

                    for imp in getattr(entry, "imports", []) or []:
                        name = getattr(imp, "name", None)
                        api = name.decode(errors="replace") if isinstance(name, bytes) else (str(name) if name is not None else "unknown")
                        ordinal_raw = getattr(imp, "ordinal", None)
                        hint_raw = getattr(imp, "hint", None)
                        ordinal = int(ordinal_raw) if ordinal_raw is not None else None
                        hint = int(hint_raw) if hint_raw is not None else None
                        suspicious = api.lower() in self._suspicious_set

                        self._imports.append(
                            ImportEntry(
                                dll=dll,
                                api=api,
                                ordinal=ordinal,
                                hint=hint,
                                delay_import=True,
                                suspicious=suspicious,
                            )
                        )
        except Exception:
            pass

        self._mark_parsed()

    def display(self) -> None:
        """Display parsed imports in Rich tables."""

        if not self._parsed and not self._imports:
            self.parse()

        table = Table(
            box=None,
            show_lines=False,
        )
        table.add_column("DLL", style="bold cyan")
        table.add_column("API", style="white")
        table.add_column("Ordinal", justify="right")
        table.add_column("Hint", justify="right")
        table.add_column("Delay", justify="center")
        table.add_column("Suspicious", justify="center")

        suspicious_count = 0

        for imp in self._imports:
            if imp.suspicious:
                suspicious_count += 1
            table.add_row(
                imp.dll,
                imp.api,
                str(imp.ordinal) if imp.ordinal is not None else "-",
                str(imp.hint) if imp.hint is not None else "-",
                "Yes" if imp.delay_import else "No",
                "Yes" if imp.suspicious else "No",
            )

        title = f"PE Imports (Total: {len(self._imports)}, Suspicious: {suspicious_count})"
        self._console.print(
            Panel(table, title=title, border_style="cyan", padding=(0, 1))
        )

    def summary(self) -> dict[str, Any]:
        """Return JSON-serializable summary of imports."""

        if not self._parsed and not self._imports:
            self.parse()

        suspicious = [imp.to_dict() for imp in self._imports if imp.suspicious]
        return {
            "type": "PE",
            "imports": [imp.to_dict() for imp in self._imports],
            "count": len(self._imports),
            "suspicious_count": len(suspicious),
            "suspicious": suspicious,
        }

    def to_dict(self) -> dict[str, Any]:
        """Alias for summary()."""

        return self.summary()

    def to_json(self) -> str:
        """Alias for BinaryParserBase.to_json()."""

        return super().to_json()

