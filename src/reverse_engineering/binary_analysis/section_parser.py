from __future__ import annotations

import math
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
class SectionInfo:
    """PE section information."""

    name: str
    virtual_address: int
    raw_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: list[str]
    executable: bool
    writable: bool
    readable: bool
    suspicious: bool

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""
        return {
            "name": self.name,
            "virtual_address": self.virtual_address,
            "raw_address": self.raw_address,
            "virtual_size": self.virtual_size,
            "raw_size": self.raw_size,
            "entropy": self.entropy,
            "characteristics": self.characteristics,
            "executable": self.executable,
            "writable": self.writable,
            "readable": self.readable,
            "suspicious": self.suspicious,
        }


class SectionParser(BinaryParserBase):
    """Parse PE sections and compute entropy to highlight suspicious ones."""

    def __init__(
        self,
        file_path: Path,
        *,
        console: Optional[Console] = None,
        config: Optional[ConfigManager] = None,
    ) -> None:
        """Initialize SectionParser."""
        super().__init__(file_path, console=console, config=config)
        self._pe: Optional[pefile.PE] = None
        self._sections: list[SectionInfo] = []

    def validate(self) -> None:
        """Validate PE input using pefile."""
        super().validate()
        try:
            pefile.PE(str(self.file_path), fast_load=True)
        except pefile.PEFormatError as exc:
            raise ValueError(f"Not a valid PE file: {self.file_path}") from exc

    @staticmethod
    def _entropy(data: bytes) -> float:
        """Compute Shannon entropy."""
        if not data:
            return 0.0
        length = len(data)
        if length <= 1:
            return 0.0

        freq = [0] * 256
        for b in data:
            freq[b] += 1

        ent = 0.0
        for c in freq:
            if c == 0:
                continue
            p = c / length
            ent -= p * math.log2(p)
        return float(ent)

    @staticmethod
    def _characteristics_to_flags(chars: int) -> tuple[list[str], bool, bool, bool]:
        """Map common PE section characteristic bits."""
        mapping = {
            0x20000000: ("IMAGE_SCN_MEM_EXECUTE", True, False, False),
            0x80000000: ("IMAGE_SCN_MEM_READ", False, False, True),
            0x40000000: ("IMAGE_SCN_MEM_WRITE", False, True, False),
        }

        names: list[str] = []
        executable = False
        writable = False
        readable = False

        for bit, (name, ex, wr, rd) in mapping.items():
            if chars & bit:
                names.append(name)
                executable = executable or ex
                writable = writable or wr
                readable = readable or rd

        # Also include raw characteristics name hints.
        if not names:
            names.append(hex(chars))

        return names, executable, writable, readable

    def parse(self) -> None:
        """Parse PE sections and compute entropy for each section."""
        self.validate()

        try:
            self._pe = pefile.PE(str(self.file_path), fast_load=False)
        except Exception as exc:
            raise OSError(f"Failed to load PE for sections: {self.file_path}") from exc

        pe = self._pe
        # Suspicious heuristics thresholds (configurable best-effort).
        entropy_threshold = float(self._config.get("reverse.entropy.suspicious", 7.2))
        rwx_suspicious = bool(self._config.get("reverse.sections.rwx_suspicious", True))

        self._sections = []

        for sec in pe.sections:
            name = (sec.Name or b"").split(b"\x00", 1)[0].decode(errors="replace")
            virtual_address = int(getattr(sec, "VirtualAddress", 0))
            raw_address = int(getattr(sec, "PointerToRawData", 0))
            virtual_size = int(getattr(sec, "Misc_VirtualSize", 0))
            raw_size = int(getattr(sec, "SizeOfRawData", 0))
            chars_raw = int(getattr(sec, "Characteristics", 0))

            # Extract raw data bytes for entropy. Handle missing raw data.
            data = b""
            try:
                if raw_size > 0 and raw_address > 0:
                    with open(self.file_path, "rb") as f:
                        f.seek(raw_address)
                        data = f.read(raw_size)
            except Exception:
                data = b""

            entropy = self._entropy(data)
            characteristics, executable, writable, readable = self._characteristics_to_flags(chars_raw)

            suspicious = entropy >= entropy_threshold
            if rwx_suspicious and executable and writable:
                suspicious = True

            self._sections.append(
                SectionInfo(
                    name=name,
                    virtual_address=virtual_address,
                    raw_address=raw_address,
                    virtual_size=virtual_size,
                    raw_size=raw_size,
                    entropy=entropy,
                    characteristics=characteristics,
                    executable=executable,
                    writable=writable,
                    readable=readable,
                    suspicious=suspicious,
                )
            )

        self._mark_parsed()

    def display(self) -> None:
        """Display extracted sections."""
        if not self._parsed and not self._sections:
            self.parse()

        table = Table(box=None, show_lines=False)
        table.add_column("Name", style="bold cyan")
        table.add_column("VA", justify="right")
        table.add_column("Raw", justify="right")
        table.add_column("VirtSize", justify="right")
        table.add_column("RawSize", justify="right")
        table.add_column("Entropy", justify="right")
        table.add_column("Flags", style="white")
        table.add_column("RWX", style="white")
        table.add_column("Suspicious", style="white")

        for sec in self._sections:
            flags = ", ".join(sec.characteristics) if sec.characteristics else ""  # type: ignore[truthy-function]
            rwx = (
                ("X" if sec.executable else "-")
                + ("W" if sec.writable else "-")
                + ("R" if sec.readable else "-")
            )
            susp = "Yes" if sec.suspicious else "No"
            table.add_row(
                sec.name,
                hex(sec.virtual_address),
                hex(sec.raw_address),
                str(sec.virtual_size),
                str(sec.raw_size),
                f"{sec.entropy:.3f}",
                flags,
                rwx,
                susp,
            )

        self._console.print(
            Panel(table, title="PE Sections (Entropy + Flags)", border_style="cyan", padding=(0, 1))
        )

    def summary(self) -> dict[str, Any]:
        """Return summary of parsed sections."""
        if not self._parsed and not self._sections:
            self.parse()

        return {
            "type": "PE",
            "sections": [s.to_dict() for s in self._sections],
            "count": len(self._sections),
        }

    def to_dict(self) -> dict[str, Any]:
        """Alias for summary()."""
        return self.summary()

    def to_json(self) -> str:
        """Alias for BinaryParserBase.to_json()."""
        return super().to_json()

