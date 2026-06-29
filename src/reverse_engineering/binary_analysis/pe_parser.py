from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import pefile
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.logger import setup_logger

SUSPICIOUS_IMPORTS = {
    "VirtualAlloc",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "IsDebuggerPresent",
    "RegOpenKey",
    "InternetOpen",
    "WSAStartup",
}


def _shannon_entropy(data: bytes) -> float:
    """Compute Shannon entropy for a byte sequence."""
    if not data:
        return 0.0

    counts = [0] * 256
    for b in data:
        counts[b] += 1

    ent = 0.0
    length = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        ent -= p * math.log2(p)
    return ent


def _subsystem_to_str(subsystem_value: Optional[int]) -> Optional[str]:
    if subsystem_value is None:
        return None

    mapping = {
        1: "Native",
        2: "Windows GUI",
        3: "Windows CUI",
        7: "POSIX CUI",
        9: "Windows CE GUI",
        10: "EFI Application",
        11: "EFI Boot Service Driver",
        12: "EFI Runtime Driver",
        13: "EFI ROM",
        14: "Xbox",
    }
    return mapping.get(subsystem_value, str(subsystem_value))


def _classify_subsystem(subsystem_value: Optional[int]) -> Optional[str]:
    if subsystem_value is None:
        return None

    # As requested: GUI/Console/Driver.
    # GUI => 2, Console => 3. Driver typically uses subsystem 1 (native) or others,
    # but PE "Driver" isn't a dedicated Subsystem value everywhere.
    if subsystem_value == 2:
        return "GUI"
    if subsystem_value == 3:
        return "Console"

    # Heuristic for driver-like values
    if subsystem_value in (1, 7, 10, 11, 12, 13):
        return "Driver"

    return _subsystem_to_str(subsystem_value)


def _machine_to_arch(machine: int) -> str:
    if machine == 0x8664:
        return "x64"
    if machine == 0x014c:
        return "x86"
    if machine in (0x01C4, 0x01C0, 0xAA64):
        return "ARM"
    return hex(machine)


def _get_section_name(section: pefile.SectionStructure) -> str:
    raw = getattr(section, "Name", b"")
    if isinstance(raw, bytes):
        return raw.rstrip(b"\x00").decode(errors="replace")
    return str(raw)


def _section_characteristics_to_flags(ch: int) -> tuple[bool, bool, bool]:
    # As requested: readable/writable/executable.
    # PE flags:
    #   IMAGE_SCN_MEM_READ    0x40000000
    #   IMAGE_SCN_MEM_WRITE   0x80000000
    #   IMAGE_SCN_MEM_EXECUTE 0x20000000
    readable = bool(ch & 0x40000000)
    writable = bool(ch & 0x80000000)
    executable = bool(ch & 0x20000000)
    return readable, writable, executable


@dataclass(frozen=True)
class _PEHashes:
    md5: Optional[str]
    sha1: Optional[str]
    sha256: Optional[str]

    def to_dict(self) -> dict[str, Optional[str]]:
        return {"md5": self.md5, "sha1": self.sha1, "sha256": self.sha256}


class PEAnalyzer:
    """Production-grade PE analyzer module based on pefile.

    Methods are designed to be called individually from the CLI,
    but `generate_report` can aggregate them into a Rich terminal report.
    """

    def __init__(self, *, console: Optional[Console] = None) -> None:
        self._console = console or Console()
        self._logger = setup_logger(self.__class__.__name__)

    def _load_pe(self, filepath: Path) -> pefile.PE:
        """Load a PE using pefile with robust error handling."""
        # Existence and permissions are handled by callers/CLI,
        # but we keep defense-in-depth.
        if not filepath.exists():
            raise FileNotFoundError(str(filepath))
        if not filepath.is_file():
            raise IsADirectoryError(str(filepath))

        try:
            return pefile.PE(str(filepath), fast_load=False)
        except pefile.PEFormatError as exc:
            raise ValueError(f"Not a valid PE file: {filepath}") from exc
        except PermissionError:
            raise
        except OSError as exc:
            raise OSError(f"Failed to open PE file: {filepath}") from exc

    def _compute_hashes_light(self, filepath: Path) -> _PEHashes:
        # Keep local to this module (avoid cross-dependencies).
        import hashlib

        md5_h = hashlib.md5(usedforsecurity=False)  # nosec B324
        sha1_h = hashlib.sha1(usedforsecurity=False)  # nosec B324
        sha256_h = hashlib.sha256()

        chunk = 1024 * 1024

        try:
            with filepath.open("rb") as f:
                while True:
                    b = f.read(chunk)
                    if not b:
                        break
                    md5_h.update(b)
                    sha1_h.update(b)
                    sha256_h.update(b)
        except PermissionError:
            raise
        except OSError as exc:
            raise OSError(f"Failed to read file for hashing: {filepath}") from exc

        return _PEHashes(md5=md5_h.hexdigest(), sha1=sha1_h.hexdigest(), sha256=sha256_h.hexdigest())

    def get_metadata(self, filepath: Path | str) -> dict[str, Any]:
        """Extract general PE metadata as a dictionary."""
        path = Path(filepath)
        pe = self._load_pe(path)

        hashes = self._compute_hashes_light(path)

        optional = getattr(pe, "OPTIONAL_HEADER", None)
        file_header = getattr(pe, "FILE_HEADER", None)

        machine_arch = "unknown"
        timestamp: Optional[str] = None
        entry_point = 0
        image_base = 0
        subsystem_raw: Optional[int] = None
        number_of_sections: Optional[int] = None

        if file_header is not None:
            number_of_sections = getattr(file_header, "NumberOfSections", None)
            machine_arch = _machine_to_arch(int(getattr(file_header, "Machine", 0) or 0))
            ts_raw = getattr(file_header, "TimeDateStamp", None)
            if ts_raw:
                # Convert to UTC string.
                import datetime

                try:
                    dt = datetime.datetime.utcfromtimestamp(int(ts_raw))
                    timestamp = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                except Exception:
                    timestamp = None

        if optional is not None:
            entry_point = int(getattr(optional, "AddressOfEntryPoint", 0) or 0)
            image_base = int(getattr(optional, "ImageBase", 0) or 0)
            subsystem_raw = getattr(optional, "Subsystem", None)

        subsystem = _classify_subsystem(int(subsystem_raw)) if subsystem_raw is not None else None

        return {
            "hashes": hashes.to_dict(),
            "compile_timestamp": timestamp,
            "machine_type": machine_arch,
            "subsystem": subsystem,
            "entry_point": entry_point,
            "image_base": image_base,
            "number_of_sections": number_of_sections,
        }

    def get_sections(self, filepath: Path | str) -> list[dict[str, Any]]:
        """Extract PE section information including entropy and RWX flags."""
        path = Path(filepath)
        pe = self._load_pe(path)

        sections: list[dict[str, Any]] = []
        for section in pe.sections:
            name = _get_section_name(section)
            virtual_address = int(getattr(section, "VirtualAddress", 0) or 0)
            raw_size = int(getattr(section, "SizeOfRawData", 0) or 0)
            ch = int(getattr(section, "Characteristics", 0) or 0)

            readable, writable, executable = _section_characteristics_to_flags(ch)

            try:
                raw_data = section.get_data()
            except Exception:
                raw_data = b""

            entropy = _shannon_entropy(raw_data)
            possibly_packed = entropy > 7.0

            sections.append(
                {
                    "name": name,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "characteristics": {
                        "readable": readable,
                        "writable": writable,
                        "executable": executable,
                    },
                    "entropy": entropy,
                    "possibly_packed": possibly_packed,
                }
            )

        return sections

    def get_imports(self, filepath: Path | str) -> dict[str, list[str]]:
        """Extract imports grouped by DLL name."""
        path = Path(filepath)
        pe = self._load_pe(path)

        imports: dict[str, list[str]] = {}
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        except Exception:
            # If import directory missing, treat as empty.
            return {}

        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return {}

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = getattr(entry, "dll", b"")
            if isinstance(dll_name, bytes):
                dll_str = dll_name.decode(errors="replace")
            else:
                dll_str = str(dll_name)

            imported_functions: list[str] = []
            for imp in entry.imports:
                fn = getattr(imp, "name", None)
                if fn is None:
                    continue
                if isinstance(fn, bytes):
                    imported_functions.append(fn.decode(errors="replace"))
                else:
                    imported_functions.append(str(fn))

            imports[dll_str] = imported_functions

        return imports

    def get_exports(self, filepath: Path | str) -> list[dict[str, Any]]:
        """Extract export table entries."""
        path = Path(filepath)
        pe = self._load_pe(path)

        exports: list[dict[str, Any]] = []
        try:
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )
        except Exception:
            return []

        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return []

        directory = pe.DIRECTORY_ENTRY_EXPORT
        for exp in getattr(directory, "symbols", []) or []:
            name = getattr(exp, "name", None)
            if isinstance(name, bytes):
                export_name = name.decode(errors="replace")
            elif name is None:
                export_name = None
            else:
                export_name = str(name)

            ordinal = getattr(exp, "ordinal", None)
            # Address: use exp.address if available.
            address = getattr(exp, "address", None)

            exports.append({"export_name": export_name, "ordinal": ordinal, "address": address})

        return exports

    def check_anomalies(self, filepath: Path | str) -> list[str]:
        """Run anomaly checks and return a list of descriptive strings."""
        path = Path(filepath)

        anomalies: list[str] = []

        # Load PE once and do best-effort header mismatch checks.
        try:
            pe = self._load_pe(path)
        except ValueError:
            # Preserve expected behavior for non-PE.
            raise

        # 1) Entropy rule
        try:
            for section in pe.sections:
                try:
                    raw_data = section.get_data()
                except Exception:
                    raw_data = b""
                entropy = _shannon_entropy(raw_data)
                if entropy > 7.2:
                    anomalies.append(
                        f"Section entropy high (>7.2): { _get_section_name(section) } entropy={entropy:.4f}"
                    )
        except Exception:
            pass

        # 2) No imports
        imports = {}
        try:
            imports = self.get_imports(path)
        except Exception:
            imports = {}
        if not imports:
            anomalies.append("No imports found (suspicious)")

        # 3) Mismatched headers (best-effort)
        try:
            optional = getattr(pe, "OPTIONAL_HEADER", None)
            if optional is not None:
                addr_entry = int(getattr(optional, "AddressOfEntryPoint", 0) or 0)
                # Entry point should land in some section RVA range.
                entry_in_section = False
                for section in pe.sections:
                    va = int(getattr(section, "VirtualAddress", 0) or 0)
                    vsz = int(getattr(section, "Misc_VirtualSize", 0) or 0)
                    if vsz == 0:
                        vsz = int(getattr(section, "SizeOfRawData", 0) or 0)
                    if va <= addr_entry < (va + vsz):
                        entry_in_section = True
                        break
                if not entry_in_section and addr_entry != 0:
                    anomalies.append("Entry point does not fall within any section (header mismatch)")
        except Exception:
            pass

        # 4) Non-standard section names
        try:
            standard_names = {".text", ".rdata", ".data", ".idata", ".rsrc", ".reloc", ".bss"}
            for section in pe.sections:
                name = _get_section_name(section)
                if not name.startswith(".") or name.lower() not in standard_names:
                    # Keep as warning for any unknown names; packers often add .packed/.xdata etc.
                    if name.strip() and len(name) > 0:
                        anomalies.append(f"Non-standard section name: {name}")
        except Exception:
            pass

        # 5) W^X violation (writable and executable)
        try:
            for section in pe.sections:
                ch = int(getattr(section, "Characteristics", 0) or 0)
                readable, writable, executable = _section_characteristics_to_flags(ch)
                if writable and executable:
                    anomalies.append(
                        f"W^X violation: section { _get_section_name(section) } is writable and executable"
                    )
        except Exception:
            pass

        return anomalies

    def generate_report(self, filepath: Path | str, *, options: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """Generate a Rich report or JSON report.

        Args:
            filepath: PE file path.
            options:
              - sections/imports/exports/full/json/console toggles.

        Returns:
            Parsed data structure (JSON-serializable).
        """
        opts = options or {}
        want_sections = bool(opts.get("sections"))
        want_imports = bool(opts.get("imports"))
        want_exports = bool(opts.get("exports"))
        want_full = bool(opts.get("full"))
        want_json = bool(opts.get("json"))
        console: Console = opts.get("console") or self._console

        data: dict[str, Any] = {}

        metadata = self.get_metadata(filepath)
        sections = self.get_sections(filepath)
        imports = self.get_imports(filepath)
        exports = self.get_exports(filepath)
        anomalies = self.check_anomalies(filepath)

        data.update(
            {
                "metadata": metadata,
                "sections": sections,
                "imports": imports,
                "exports": exports,
                "anomalies": anomalies,
            }
        )

        if want_json:
            return data

        # Rich output
        def _color_line(msg: str) -> str:
            lowered = msg.lower()
            if any(k in lowered for k in ("suspicious", "violation", ">7.2", "entropy high")):
                return f"[red]{msg}[/red]"
            if any(k in lowered for k in ("warning", "non-standard", "mismatch", "no imports")):
                return f"[yellow]{msg}[/yellow]"
            return f"[green]{msg}[/green]"

        if want_full or want_sections:
            t = Table(title="Sections", box=None, show_edge=False)
            t.add_column("Name", style="bold")
            t.add_column("VA", style="cyan")
            t.add_column("Raw Size", style="white")
            t.add_column("Entropy", style="magenta")
            t.add_column("Flags", style="white")

            for s in sections:
                flags = []
                if s["characteristics"]["readable"]:
                    flags.append("R")
                if s["characteristics"]["writable"]:
                    flags.append("W")
                if s["characteristics"]["executable"]:
                    flags.append("X")
                packed = " (possibly packed)" if s.get("possibly_packed") else ""
                entropy_text = f"{s['entropy']:.4f}{packed}"
                t.add_row(s["name"], hex(int(s["virtual_address"])), str(s["raw_size"]), entropy_text, "/".join(flags))

            console.print(Panel(t, border_style="cyan", padding=(0, 1)))

        if want_full or want_imports:
            t = Table(title="Imports", box=None, show_edge=False)
            t.add_column("DLL", style="bold cyan")
            t.add_column("Functions", style="white")

            if not imports:
                t.add_row("<none>", "[yellow]none[/yellow]")
            else:
                for dll, funcs in imports.items():
                    suspicious_hits = [f for f in funcs if f in SUSPICIOUS_IMPORTS]
                    funcs_text = ", ".join(funcs[:50]) + (", ..." if len(funcs) > 50 else "")
                    if suspicious_hits:
                        funcs_text = f"[red]{funcs_text}[/red]"  # mark whole row red
                    t.add_row(dll, funcs_text)

            console.print(Panel(t, border_style="cyan", padding=(0, 1)))

        if want_full or want_exports:
            t = Table(title="Exports", box=None, show_edge=False)
            t.add_column("Name", style="bold")
            t.add_column("Ordinal", style="cyan")
            t.add_column("Address", style="white")

            if not exports:
                t.add_row("<none>", "-", "-")
            else:
                for e in exports:
                    name = e.get("export_name") or "<noname>"
                    ordinal = e.get("ordinal")
                    address = e.get("address")
                    addr_text = hex(int(address)) if isinstance(address, int) else str(address)
                    t.add_row(str(name), str(ordinal), addr_text)

            console.print(Panel(t, border_style="cyan", padding=(0, 1)))

        # Metadata + anomalies always in full mode
        if want_full:
            t = Table(title="Metadata", box=None, show_edge=False)
            t.add_column("Property", style="bold cyan")
            t.add_column("Value", style="white")

            hashes = metadata.get("hashes", {})
            t.add_row("MD5", hashes.get("md5") or "")
            t.add_row("SHA1", hashes.get("sha1") or "")
            t.add_row("SHA256", hashes.get("sha256") or "")
            t.add_row("Compile timestamp", metadata.get("compile_timestamp") or "unknown")
            t.add_row("Machine type", metadata.get("machine_type") or "unknown")
            t.add_row("Subsystem", metadata.get("subsystem") or "unknown")
            t.add_row("Entry point", hex(int(metadata.get("entry_point") or 0)))
            t.add_row("Image base", hex(int(metadata.get("image_base") or 0)))
            t.add_row("# Sections", str(metadata.get("number_of_sections") or "unknown"))

            console.print(Panel(t, border_style="cyan", padding=(0, 1)))

            an_panel = Panel(
                "\n".join(_color_line(a) for a in anomalies) if anomalies else "[green]No anomalies detected.[/green]",
                title="Anomalies",
                border_style="red" if anomalies else "green",
                padding=(1, 2),
            )
            console.print(an_panel)

        return data

