from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.config_manager import ConfigManager
from reverse_engineering.binary_analysis.base_parser import BinaryParserBase


@dataclass(frozen=True)
class ELFInfo:
    """Container for ELF extracted information."""

    architecture: str
    entry_point: Optional[int]
    abi: Optional[str]
    endian: str
    build_id: Optional[str]
    symbol_count: int
    dynamic_libs: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""

        return {
            "architecture": self.architecture,
            "entry_point": self.entry_point,
            "abi": self.abi,
            "endian": self.endian,
            "build_id": self.build_id,
            "symbol_count": self.symbol_count,
            "dynamic_libs": self.dynamic_libs,
        }


class ELFParser(BinaryParserBase):
    """Parse ELF binaries using pyelftools."""

    def __init__(
        self,
        file_path: Path,
        *,
        console: Optional[Console] = None,
        config: Optional[ConfigManager] = None,
    ) -> None:
        """Initialize ELFParser."""

        super().__init__(file_path, console=console, config=config)
        self._elf: Optional[Any] = None
        self._info: Optional[ELFInfo] = None

    def validate(self) -> None:
        """Validate that the input is an ELF file."""

        super().validate()
        from elftools.elf.elffile import ELFFile

        try:
            with self.file_path.open("rb") as f:
                elf = ELFFile(f)
                # Basic sanity: must have header with class/endianness.
                _ = elf.header
        except Exception as exc:
            raise ValueError(f"Not a valid ELF file: {self.file_path}") from exc

    @staticmethod
    def _architecture_from_class_and_machine(elf: Any) -> str:
        """Best-effort architecture string."""

        try:
            elf_class = elf.elfclass
        except Exception:
            elf_class = None

        # e_machine from header (best-effort string mapping)
        machine = None
        try:
            machine = elf.header.get("e_machine")
        except Exception:
            machine = None

        bitness = "" if elf_class is None else str(elf_class)
        arch = "ELF"
        if machine is not None:
            arch = f"{machine}"
        if bitness:
            arch = f"{arch} ({bitness})"
        return arch

    def _extract_build_id(self, elf: Any) -> Optional[str]:
        """Extract Build ID from .note.gnu.build-id when present."""
        try:
            note_sections = elf.iter_sections()
        except Exception:
            return None

        build_id: Optional[str] = None
        try:
            for sec in note_sections:
                name = sec.name
                if name != ".note.gnu.build-id":
                    continue
                # Section uses iter_notes in pyelftools.
                try:
                    for note in sec.iter_notes():
                        n_name = getattr(note, "n_name", None)
                        if n_name != "GNU":
                            continue
                        desc = getattr(note, "n_desc", None)
                        if desc is None:
                            continue
                        # desc is typically bytes.
                        if isinstance(desc, (bytes, bytearray)):
                            build_id = bytes(desc).hex()
                        else:
                            build_id = str(desc)
                        return build_id
                except Exception:
                    continue
        except Exception:
            return None

        return build_id

    def parse(self) -> None:
        """Parse ELF headers, sections, symbols, and dynamic libraries."""

        self.validate()

        from elftools.elf.elffile import ELFFile

        try:
            with self.file_path.open("rb") as f:
                self._elf = ELFFile(f)
                elf = self._elf

                endian = "little" if getattr(elf, "little_endian", False) else "big"
                abi: Optional[str] = None
                try:
                    e_ident = elf.header.get("e_ident")
                    # EI_OSABI mapping best-effort.
                    if isinstance(e_ident, dict):
                        osabi = e_ident.get("EI_OSABI")
                        abi = str(osabi) if osabi is not None else None
                except Exception:
                    abi = None

                entry_point = None
                try:
                    entry_point_val = elf.header.get("e_entry")
                    entry_point = int(entry_point_val) if entry_point_val is not None else None
                except Exception:
                    entry_point = None

                architecture = self._architecture_from_class_and_machine(elf)

                build_id = self._extract_build_id(elf)

                # Symbols: count from .symtab and .dynsym.
                symbol_count = 0
                try:
                    for sec in elf.iter_sections():
                        if sec is None:
                            continue
                        if sec.__class__.__name__ == "SymbolTableSection":
                            symbol_count += int(getattr(sec, "num_symbols", 0) or 0)
                        elif hasattr(sec, "iter_symbols"):
                            # Best-effort: dynsym
                            try:
                                symbol_count += sum(1 for _ in sec.iter_symbols())
                            except Exception:
                                pass
                except Exception:
                    symbol_count = 0

                # Dynamic libs from DT_NEEDED entries in .dynamic
                dynamic_libs: list[str] = []
                try:
                    dynamic = elf.get_section_by_name(".dynamic")
                    if dynamic is not None:
                        for tag in dynamic.iter_tags():
                            if tag.entry.d_tag == "DT_NEEDED":
                                val = tag.needed
                                if isinstance(val, bytes):
                                    dynamic_libs.append(val.decode(errors="replace"))
                                else:
                                    dynamic_libs.append(str(val))
                except Exception:
                    dynamic_libs = []

                self._info = ELFInfo(
                    architecture=architecture,
                    entry_point=entry_point,
                    abi=abi,
                    endian=endian,
                    build_id=build_id,
                    symbol_count=symbol_count,
                    dynamic_libs=sorted(set(dynamic_libs)),
                )

        except PermissionError:
            raise
        except Exception as exc:
            raise OSError(f"Failed to parse ELF: {self.file_path}") from exc

        self._maybe_display_hashes()
        self._mark_parsed()

    def display(self) -> None:
        """Display ELF extracted information."""

        if not self._parsed and self._info is None:
            self.parse()

        if self._info is None:
            raise RuntimeError("ELFParser has no parsed info")

        info = self._info

        table = Table(box=None, show_lines=False)
        table.add_column("Property", style="bold cyan")
        table.add_column("Value", style="white")

        table.add_row("Architecture", info.architecture)
        table.add_row("Endian", info.endian)
        table.add_row("ABI", info.abi or "unknown")
        table.add_row("Entry Point", hex(info.entry_point) if info.entry_point is not None else "unknown")
        table.add_row("Build ID", info.build_id or "unknown")
        table.add_row("Symbols", str(info.symbol_count))
        table.add_row("Dynamic Libraries", str(len(info.dynamic_libs)))

        self._console.print(
            Panel(table, title="ELF Header / Metadata", border_style="cyan", padding=(0, 1))
        )

        if info.dynamic_libs:
            libs_table = Table(box=None, show_lines=False)
            libs_table.add_column("Library", style="green")
            for lib in info.dynamic_libs:
                libs_table.add_row(lib)
            self._console.print(
                Panel(libs_table, title="Dynamic Libraries (DT_NEEDED)", border_style="cyan", padding=(0, 1))
            )

    def summary(self) -> dict[str, Any]:
        """Return JSON-serializable summary."""

        if not self._parsed and self._info is None:
            self.parse()
        if self._info is None:
            raise RuntimeError("ELFParser summary requested before parse")

        return {
            "type": "ELF",
            **self._info.to_dict(),
            "hashes": (self._ensure_hashes().to_dict() if self._hashes is not None else None),
        }

    def to_dict(self) -> dict[str, Any]:
        """Alias for summary()."""

        return self.summary()

    def to_json(self) -> str:
        """Alias for BinaryParserBase.to_json()."""

        return super().to_json()

