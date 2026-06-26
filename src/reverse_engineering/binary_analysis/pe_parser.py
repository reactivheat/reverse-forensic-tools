from __future__ import annotations

import datetime
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
class PEGeneralInfo:
    """General PE information extracted from pefile."""

    machine: str
    timestamp: Optional[str]
    entry_point: int
    image_base: int
    subsystem: Optional[str]
    dll_characteristics: list[str]
    file_alignment: Optional[int]
    section_alignment: Optional[int]
    checksum: Optional[int]
    number_of_sections: Optional[int]
    size_of_image: Optional[int]
    overlay_present: bool
    digital_signature_present: bool
    rich_header_present: bool
    compiler_timestamp: Optional[str]


class PEParser(BinaryParserBase):
    """Parse Portable Executable (PE) binaries using pefile."""

    def __init__(
        self,
        file_path: Path,
        *,
        console: Optional[Console] = None,
        config: Optional[ConfigManager] = None,
    ) -> None:
        """Initialize PEParser.

        Args:
            file_path: PE file path.
            console: Optional Rich console.
            config: Optional ConfigManager.
        """
        super().__init__(file_path, console=console, config=config)
        self._pe: Optional[pefile.PE] = None
        self._info: Optional[PEGeneralInfo] = None

    def validate(self) -> None:
        """Validate PE input.

        Raises:
            ValueError: If file does not look like a PE.
            PermissionError: If file cannot be read.
            FileNotFoundError: If file missing.
            IsADirectoryError: If path is a directory.
        """
        super().validate()

        # Quick validation via DOS/PE magic.
        try:
            pe = pefile.PE(str(self.file_path), fast_load=True)
        except pefile.PEFormatError as exc:
            raise ValueError(f"Not a valid PE file: {self.file_path}") from exc
        except Exception as exc:
            raise ValueError(f"Failed to load PE for validation: {self.file_path}") from exc

        # Ensure it has an entry point and header.
        if not hasattr(pe, "OPTIONAL_HEADER"):
            raise ValueError(f"PE missing OPTIONAL_HEADER: {self.file_path}")

    def _coerce_timestamp(self, ts: Optional[int]) -> Optional[str]:
        if ts is None:
            return None
        try:
            dt = datetime.datetime.utcfromtimestamp(ts)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, OverflowError, ValueError):
            return None

    @staticmethod
    def _machine_to_string(machine: int) -> str:
        # Common PE machine identifiers.
        mapping = {
            0x014c: "Intel 386",
            0x8664: "x64",
            0x0200: "Intel Itanium",
            0x01c0: "ARM",
            0x01c4: "ARMv7",
            0xAA64: "ARM64",
            0x014D: "AMD",
        }
        return mapping.get(machine, hex(machine))

    def parse(self) -> None:
        """Parse the PE file and populate internal state."""
        self.validate()

        try:
            # Load full info (sections, overlay checks, signatures detection may rely on it).
            self._pe = pefile.PE(str(self.file_path), fast_load=False)
        except pefile.PEFormatError as exc:
            raise ValueError(f"Not a valid PE file: {self.file_path}") from exc
        except PermissionError:
            raise
        except OSError as exc:
            raise OSError(f"Failed to open PE file: {self.file_path}") from exc

        pe = self._pe
        optional = getattr(pe, "OPTIONAL_HEADER", None)
        file_header = getattr(pe, "FILE_HEADER", None)

        machine_str = "unknown"
        timestamp_str: Optional[str] = None
        entry_point = 0
        image_base = 0

        subsystem: Optional[str] = None
        dll_characteristics: list[str] = []
        file_alignment: Optional[int] = None
        section_alignment: Optional[int] = None
        checksum: Optional[int] = None
        number_of_sections: Optional[int] = None
        size_of_image: Optional[int] = None

        overlay_present = False
        digital_signature_present = False
        rich_header_present = False
        compiler_timestamp: Optional[str] = None

        if file_header is not None:
            machine_raw = getattr(file_header, "Machine", 0)
            machine_str = self._machine_to_string(int(machine_raw))
            ts_raw = getattr(file_header, "TimeDateStamp", None)
            timestamp_str = self._coerce_timestamp(ts_raw)
            number_of_sections = getattr(file_header, "NumberOfSections", None)

        if optional is not None:
            entry_point = int(getattr(optional, "AddressOfEntryPoint", 0))
            image_base = int(getattr(optional, "ImageBase", 0))
            checksum = getattr(optional, "CheckSum", None)
            file_alignment = getattr(optional, "FileAlignment", None)
            section_alignment = getattr(optional, "SectionAlignment", None)
            size_of_image = getattr(optional, "SizeOfImage", None)

            # Subsystem mapping is not provided by pefile directly; use numeric value.
            subsystem_raw = getattr(optional, "Subsystem", None)
            if subsystem_raw is not None:
                subsystem = str(subsystem_raw)

            dll_chars_raw = getattr(optional, "DllCharacteristics", 0)
            try:
                dll_characteristics_val = int(dll_chars_raw)
                # Interpret common flags if possible.
                flag_map = {
                    0x0040: "Dynamic base",
                    0x0100: "NX compatible",
                    0x0400: "No SEH",
                    0x0800: "No CFG",
                    0x4000: "No Isolation",
                    0x8000: "No Appcontainer",
                }
                for bit, name in flag_map.items():
                    if dll_characteristics_val & bit:
                        dll_characteristics.append(name)
            except (TypeError, ValueError):
                dll_characteristics = []

        # Overlay detection heuristic: overlay is data after the last section.
        try:
            pe.parse_data_directories()
        except Exception:
            # best-effort
            pass

        try:
            # pefile computes overlay size with get_overlay()
            overlay_data = pe.get_overlay()
            overlay_present = bool(overlay_data)
        except Exception:
            overlay_present = False

        # Digital signature detection: security directory / certificate table.
        try:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
            ]
            # pefile may store .VirtualAddress/.Size
            sig_size = int(getattr(security_dir, "Size", 0) or 0)
            digital_signature_present = sig_size > 0
        except Exception:
            digital_signature_present = False

        # Rich header detection is complicated; best-effort heuristic.
        try:
            # pefile has helper to get_rich_header?
            if hasattr(pe, "get_rich_header"):
                rh = pe.get_rich_header()
                rich_header_present = rh is not None
            else:
                rich_header_present = False
        except Exception:
            rich_header_present = False

        # Compiler timestamp may not be directly available; best-effort via rich header.
        if rich_header_present:
            try:
                # If pefile exposes rich header metadata
                rh = pe.get_rich_header() if hasattr(pe, "get_rich_header") else None
                if isinstance(rh, dict):
                    compiler_ts = rh.get("timestamp")
                    compiler_timestamp = self._coerce_timestamp(int(compiler_ts)) if compiler_ts else None
            except Exception:
                compiler_timestamp = None

        self._info = PEGeneralInfo(
            machine=machine_str,
            timestamp=timestamp_str,
            entry_point=entry_point,
            image_base=image_base,
            subsystem=subsystem,
            dll_characteristics=dll_characteristics,
            file_alignment=file_alignment if file_alignment is None else int(file_alignment),
            section_alignment=section_alignment
            if section_alignment is None
            else int(section_alignment),
            checksum=checksum if checksum is None else int(checksum),
            number_of_sections=number_of_sections
            if number_of_sections is None
            else int(number_of_sections),
            size_of_image=size_of_image if size_of_image is None else int(size_of_image),
            overlay_present=overlay_present,
            digital_signature_present=digital_signature_present,
            rich_header_present=rich_header_present,
            compiler_timestamp=compiler_timestamp,
        )

        self._maybe_display_hashes()
        self._mark_parsed()

    def display(self) -> None:
        """Display PE general information in Rich panels/tables."""
        if self._info is None:
            if not self._parsed:
                self.parse()
            if self._info is None:
                raise RuntimeError("PEParser has no parsed info to display")

        info = self._info

        table = Table(box=None, show_lines=False)
        table.add_column("Property", style="bold cyan")
        table.add_column("Value", style="white")

        table.add_row("Machine", info.machine)
        table.add_row("Timestamp", info.timestamp or "unknown")
        table.add_row("Entry Point", hex(info.entry_point))
        table.add_row("Image Base", hex(info.image_base))
        table.add_row("Subsystem", info.subsystem or "unknown")
        table.add_row(
            "DLL Characteristics",
            ", ".join(info.dll_characteristics) if info.dll_characteristics else "none",
        )
        table.add_row(
            "File Alignment",
            str(info.file_alignment) if info.file_alignment is not None else "unknown",
        )
        table.add_row(
            "Section Alignment",
            str(info.section_alignment)
            if info.section_alignment is not None
            else "unknown",
        )
        table.add_row(
            "Checksum",
            str(info.checksum) if info.checksum is not None else "unknown",
        )
        table.add_row(
            "Sections",
            str(info.number_of_sections)
            if info.number_of_sections is not None
            else "unknown",
        )
        table.add_row(
            "Size Of Image",
            str(info.size_of_image) if info.size_of_image is not None else "unknown",
        )
        table.add_row("Overlay", "Yes" if info.overlay_present else "No")
        table.add_row(
            "Signed",
            "Yes" if info.digital_signature_present else "No",
        )
        table.add_row("Rich Header", "Yes" if info.rich_header_present else "No")
        table.add_row(
            "Compiler Timestamp",
            info.compiler_timestamp or "unknown",
        )

        self._console.print(Panel(table, title="PE General Information", border_style="cyan", padding=(0, 1)))

    def summary(self) -> dict[str, Any]:
        """Return PE parsing summary."""
        if self._info is None:
            if not self._parsed:
                self.parse()
            if self._info is None:
                raise RuntimeError("PEParser summary requested before parse")

        info = self._info
        return {
            "type": "PE",
            "machine": info.machine,
            "timestamp": info.timestamp,
            "entry_point": info.entry_point,
            "image_base": info.image_base,
            "subsystem": info.subsystem,
            "dll_characteristics": info.dll_characteristics,
            "file_alignment": info.file_alignment,
            "section_alignment": info.section_alignment,
            "checksum": info.checksum,
            "number_of_sections": info.number_of_sections,
            "size_of_image": info.size_of_image,
            "overlay_present": info.overlay_present,
            "digital_signature_present": info.digital_signature_present,
            "rich_header_present": info.rich_header_present,
            "compiler_timestamp": info.compiler_timestamp,
            "hashes": (self._ensure_hashes().to_dict() if self._hashes is not None else None),
        }

    def to_dict(self) -> dict[str, Any]:
        """Alias for summary()."""
        return self.summary()

    def to_json(self) -> str:
        """Serialize summary to JSON."""
        return super().to_json()


