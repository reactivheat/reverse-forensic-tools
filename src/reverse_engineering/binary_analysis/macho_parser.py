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
class MachOInfo:
    """Container for Mach-O extracted information."""

    architecture: str
    entry_point: Optional[int]
    cpu_type: Optional[int]
    file_type: Optional[int]
    ncmds: Optional[int]
    segments: list[dict[str, Any]]
    sections: list[dict[str, Any]]
    commands: list[dict[str, Any]]
    libraries: list[str]

    def to_dict(self) -> dict[str, Any]:
        """Convert to JSON-serializable dict."""

        return {
            "architecture": self.architecture,
            "entry_point": self.entry_point,
            "cpu_type": self.cpu_type,
            "file_type": self.file_type,
            "ncmds": self.ncmds,
            "segments": self.segments,
            "sections": self.sections,
            "commands": self.commands,
            "libraries": self.libraries,
        }


class MachOParser(BinaryParserBase):
    """Parse Mach-O binaries (32/64 and universal/best-effort).

    This implementation prefers `macholib` for structured extraction.
    When `macholib` is not installed, it raises an ImportError with guidance.

    Supported use cases:
      - Mach-O 32
      - Mach-O 64
      - Universal (fat) binaries (best-effort: parses first architecture)
    """

    def __init__(
        self,
        file_path: Path,
        *,
        console: Optional[Console] = None,
        config: Optional[ConfigManager] = None,
    ) -> None:
        """Initialize MachOParser."""

        super().__init__(file_path, console=console, config=config)
        self._info: Optional[MachOInfo] = None

    def validate(self) -> None:
        """Validate the input file as Mach-O by checking magic bytes."""

        super().validate()

        # Mach-O magic values (32/64 + fat).
        try:
            magic = self._read_bytes(start=0, length=4)
        except OSError as exc:
            raise ValueError(f"Failed reading Mach-O magic bytes: {self.file_path}") from exc

        mach_magics = {
            b"\xfe\xed\xfa\xce",  # MH_CIGAM
            b"\xfe\xed\xfa\xcf",  # MH_CIGAM_64
            b"\xfe\xed\xfa\xce",  # duplicate safe
            b"\xce\xfa\xed\xfe",  # MH_MAGIC (little?) - byte order varies
            b"\xcf\xfa\xed\xfe",  # MH_MAGIC_64
            b"\xca\xfe\xba\xbe",  # fat/universal
            b"\xbe\xba\xfe\xca",  # fat/universal swapped
        }

        if magic not in mach_magics:
            # Keep validation strict: raise.
            raise ValueError(f"Not a recognized Mach-O file: {self.file_path}")

    @staticmethod
    def _cpu_type_to_string(cpu_type: Optional[int], cpu_subtype: Any = None) -> str:
        """Best-effort CPU architecture string."""

        if cpu_type is None:
            return "unknown"
        # Minimal mapping; macholib/capstone can provide more later.
        mapping = {
            7: "x86",
            12: "arm",
            18: "ppc",
            16777223: "x86_64",
            16777234: "arm64",
        }
        base = mapping.get(int(cpu_type), f"cpu_type={cpu_type}")
        if cpu_subtype is not None:
            return f"{base} (subtype={cpu_subtype})"
        return base

    def parse(self) -> None:
        """Parse Mach-O metadata, segments, sections, commands, and linked libraries."""

        self.validate()

        try:
            from macholib.MachO import MachO  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "macholib is required for Mach-O parsing. Install it: pip install macholib"
            ) from exc

        try:
            m = MachO(str(self.file_path))
        except Exception as exc:
            raise OSError(f"Failed to parse Mach-O: {self.file_path}") from exc

        # Universal binaries: take first header for summary; still extract all if possible.
        segments: list[dict[str, Any]] = []
        sections: list[dict[str, Any]] = []
        commands: list[dict[str, Any]] = []
        libraries: list[str] = []

        architecture = "Mach-O"
        entry_point: Optional[int] = None
        cpu_type: Optional[int] = None
        file_type: Optional[int] = None
        ncmds: Optional[int] = None

        # macholib exposes headers via `headers` list.
        headers = getattr(m, "headers", None)
        if not headers:
            # fall back: treat as single arch
            headers = [getattr(m, "header", None)]

        # Extract from first header for core metadata.
        if headers and headers[0] is not None:
            h0 = headers[0]
            hdr = getattr(h0, "header", None)
            if hdr is not None:
                cpu_type = getattr(hdr, "cputype", None)
                file_type = getattr(hdr, "filetype", None)
                ncmds = getattr(hdr, "ncmds", None)
                cpu_subtype = getattr(hdr, "cpusubtype", None)
                architecture = self._cpu_type_to_string(cpu_type, cpu_subtype)

                # Entry point is often in entryoff/entryaddr in macholib; best-effort.
                entry_point = getattr(hdr, "entryoff", None)

        # Extract segments/sections/commands by iterating load commands when available.
        try:
            # `m.commands` may exist; otherwise use headers' load commands.
            all_headers = headers or []
            if all_headers:
                for header in all_headers:
                    if header is None:
                        continue
                    # macholib header provides `commands` list (best-effort)
                    cmds = getattr(header, "commands", None)
                    if not cmds:
                        continue
                    for cmd in cmds:
                        cmd_name = cmd.__class__.__name__
                        commands.append({"command": cmd_name})

                        # Common load commands:
                        # LC_SEGMENT / LC_SEGMENT_64 provide segments & sections.
                        if hasattr(cmd, "segname") or hasattr(cmd, "segname_64"):
                            segname = getattr(cmd, "segname", None) or getattr(cmd, "segname_64", None)
                            segname_str = (
                                segname.decode(errors="replace").strip("\x00")
                                if isinstance(segname, (bytes, bytearray))
                                else str(segname) if segname is not None
                                else "unknown"
                            )
                            # best-effort VM/size
                            seg_dict: dict[str, Any] = {
                                "segment": segname_str,
                                "vmaddr": getattr(cmd, "vmaddr", None),
                                "vmsize": getattr(cmd, "vmsize", None),
                                "fileoff": getattr(cmd, "fileoff", None),
                                "filesize": getattr(cmd, "filesize", None),
                            }
                            segments.append(seg_dict)

                            # Sections container name varies.
                            sec_list = getattr(cmd, "sections", None)
                            if sec_list:
                                for sec in sec_list:
                                    secname = getattr(sec, "sectname", None) or getattr(sec, "sectname_64", None)
                                    secname_str = (
                                        secname.decode(errors="replace").strip("\x00")
                                        if isinstance(secname, (bytes, bytearray))
                                        else str(secname) if secname is not None
                                        else "unknown"
                                    )
                                    sections.append(
                                        {
                                            "segment": segname_str,
                                            "section": secname_str,
                                            "addr": getattr(sec, "addr", None),
                                            "size": getattr(sec, "size", None),
                                            "offset": getattr(sec, "offset", None),
                                        }
                                    )

                        # LC_LOAD_DYLIB provides linked libraries.
                        if cmd_name.lower().endswith("load_dylib") or hasattr(cmd, "dylib"):
                            lib = getattr(cmd, "name", None) or getattr(cmd, "dylib", None)
                            lib_str = (
                                lib.decode(errors="replace").strip("\x00")
                                if isinstance(lib, (bytes, bytearray))
                                else str(lib) if lib is not None
                                else None
                            )
                            if lib_str:
                                libraries.append(lib_str)

        except Exception:
            # best-effort: ignore extraction errors
            pass

        # De-duplicate libraries
        libraries = sorted({lib for lib in libraries if lib})

        self._info = MachOInfo(
            architecture=architecture,
            entry_point=entry_point,
            cpu_type=cpu_type,
            file_type=file_type,
            ncmds=ncmds,
            segments=segments,
            sections=sections,
            commands=commands,
            libraries=libraries,
        )

        self._maybe_display_hashes()
        self._mark_parsed()

    def display(self) -> None:
        """Display Mach-O extracted metadata."""

        if not self._parsed and self._info is None:
            self.parse()
        if self._info is None:
            raise RuntimeError("MachOParser has no parsed info")

        info = self._info

        meta_table = Table(box=None, show_lines=False)
        meta_table.add_column("Property", style="bold cyan")
        meta_table.add_column("Value", style="white")

        meta_table.add_row("Architecture", info.architecture)
        meta_table.add_row("CPU Type", str(info.cpu_type) if info.cpu_type is not None else "unknown")
        meta_table.add_row("File Type", str(info.file_type) if info.file_type is not None else "unknown")
        meta_table.add_row("Load Commands", str(info.ncmds) if info.ncmds is not None else "unknown")
        meta_table.add_row("Entry Point", hex(info.entry_point) if info.entry_point is not None else "unknown")

        self._console.print(
            Panel(meta_table, title="Mach-O Metadata", border_style="cyan", padding=(0, 1))
        )

        if info.segments:
            seg_table = Table(box=None, show_lines=False)
            seg_table.add_column("Segment", style="green")
            seg_table.add_column("VMAddr", justify="right")
            seg_table.add_column("VMSz", justify="right")
            seg_table.add_column("FileOff", justify="right")
            seg_table.add_column("FileSz", justify="right")
            for seg in info.segments:
                seg_table.add_row(
                    str(seg.get("segment", "unknown")),
                    str(seg.get("vmaddr", "unknown")),
                    str(seg.get("vmsize", "unknown")),
                    str(seg.get("fileoff", "unknown")),
                    str(seg.get("filesize", "unknown")),
                )
            self._console.print(
                Panel(seg_table, title="Segments", border_style="cyan", padding=(0, 1))
            )

        if info.sections:
            sec_table = Table(box=None, show_lines=False)
            sec_table.add_column("Section", style="green")
            sec_table.add_column("Segment", style="white")
            sec_table.add_column("Addr", justify="right")
            sec_table.add_column("Size", justify="right")
            sec_table.add_column("Offset", justify="right")
            for sec in info.sections:
                sec_table.add_row(
                    str(sec.get("section", "unknown")),
                    str(sec.get("segment", "unknown")),
                    str(sec.get("addr", "unknown")),
                    str(sec.get("size", "unknown")),
                    str(sec.get("offset", "unknown")),
                )
            self._console.print(
                Panel(sec_table, title="Sections", border_style="cyan", padding=(0, 1))
            )

        if info.libraries:
            libs_table = Table(box=None, show_lines=False)
            libs_table.add_column("Linked Library", style="green")
            for lib in info.libraries:
                libs_table.add_row(lib)
            self._console.print(
                Panel(libs_table, title="Linked Libraries", border_style="cyan", padding=(0, 1))
            )

    def summary(self) -> dict[str, Any]:
        """Return JSON-serializable summary."""

        if not self._parsed and self._info is None:
            self.parse()
        if self._info is None:
            raise RuntimeError("MachOParser summary requested before parse")

        return {
            "type": "Mach-O",
            **self._info.to_dict(),
            "hashes": (self._ensure_hashes().to_dict() if self._hashes is not None else None),
        }

    def to_dict(self) -> dict[str, Any]:
        """Alias for summary()."""
        return self.summary()

    def to_json(self) -> str:
        """Alias for BinaryParserBase.to_json()."""
        return super().to_json()

