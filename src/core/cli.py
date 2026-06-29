from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from rich.console import Console
from rich.panel import Panel

try:
    import click  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    raise SystemExit(
        "Missing dependency: click. Install with `pip install -e .`"
    )

# TYPE_CHECKING-only imports for type hints — never executed at runtime.
# All runtime imports happen lazily inside command handlers so that
# `rft --help` always works even if optional deps (e.g. python-magic) are absent.
if TYPE_CHECKING:
    from utils.hex_dump_viewer import HexDumpConfig

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

ASCII_BANNER = (
    " ██████╗███████╗██████╗ ██████╗  █████╗ \n"
    "██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗\n"
    "██║     █████╗  ██║  ██║██████╔╝███████║\n"
    "██║     ██╔══╝  ██║  ██║██╔══██╗██╔══██║\n"
    "╚██████╗███████╗██████╔╝██║  ██║██║  ██║\n"
    " ╚═════╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\n"
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _print_error(console: Console, title: str, message: str) -> None:
    """Render a red error panel — never a raw Python traceback."""
    console.print(
        Panel(
            f"[bold]{title}[/bold]\n\n{message}",
            title="[red]Error[/red]",
            border_style="red",
            padding=(1, 2),
        )
    )


def _print_coming_soon(console: Console, cmd: str) -> None:
    console.print(
        Panel(
            f"[bold yellow]{cmd}[/bold yellow] analysis module is coming soon.\n\n"
            "[dim]Track progress at: https://github.com/reactivheat/reverse-forensic-tools[/dim]",
            title="[yellow]Coming Soon[/yellow]",
            border_style="yellow",
            padding=(1, 2),
        )
    )


def _validate_file(console: Console, path: Path) -> Optional[Path]:
    """Resolve and validate a file path; return None and print error on failure."""
    try:
        resolved = path.expanduser().resolve()
    except Exception:
        resolved = path

    if not resolved.exists():
        _print_error(console, "File not found", str(resolved))
        return None
    if not resolved.is_file():
        _print_error(console, "Invalid input", f"Not a file: {resolved}")
        return None
    return resolved


# ---------------------------------------------------------------------------
# CLI group
# ---------------------------------------------------------------------------


@click.group(
    context_settings={"help_option_names": ["--help", "-h"]},
    invoke_without_command=False,
)
@click.version_option(version="1.0.0", prog_name="rft")
def cli() -> None:
    """Reverse Forensic Tools — by Operator Cedra.

    \b
    Production-grade toolkit for Reverse Engineering, DFIR,
    and Malware Analysis on Linux/Parrot OS.

    \b
    Run `rft <command> --help` for detailed usage.
    """


# ---------------------------------------------------------------------------
# hash
# ---------------------------------------------------------------------------


@cli.command("hash")
@click.argument("file", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option(
    "--algos",
    default=None,
    help="Comma-separated algorithms, e.g. sha256,sha1,md5",
)
@click.option(
    "--chunk-size",
    default=1024 * 1024,
    show_default=True,
    type=int,
    help="Read chunk size in bytes.",
)
@click.option(
    "--no-progress",
    is_flag=True,
    help="Disable the Rich progress bar.",
)
def hash_cmd(
    file: Path,
    algos: Optional[str],
    chunk_size: int,
    no_progress: bool,
) -> None:
    """Compute cryptographic hashes for FILE.

    \b
    Examples:
      rft hash malware.exe
      rft hash malware.exe --algos sha256,md5
      rft hash malware.exe --no-progress
    """
    # --- Lazy imports ---
    from rich.table import Table

    from core.config_manager import ConfigManager
    from core.logger import LoggerManager
    from utils.hash_calculator import HashCalculator

    console = Console()
    logger = LoggerManager().get_logger("rf_tools.cli")
    calculator = HashCalculator(console=console)

    target = _validate_file(console, file)
    if target is None:
        raise click.Abort()

    config = ConfigManager()
    algorithms = (
        [a.strip() for a in algos.split(",") if a.strip()]
        if algos
        else config.get("hash.algorithms", ["md5", "sha1", "sha256"])
    )

    try:
        result = calculator.compute_hashes(
            target,
            algorithms=algorithms,
            chunk_size=chunk_size,
            show_progress=not no_progress,
        )
    except PermissionError as exc:
        _print_error(console, "Permission denied", str(exc))
        raise click.Abort()
    except FileNotFoundError as exc:
        _print_error(console, "File not found", str(exc))
        raise click.Abort()
    except ValueError as exc:
        _print_error(console, "Invalid argument", str(exc))
        raise click.Abort()
    except Exception as exc:
        logger.exception("hash command failed")
        _print_error(console, "Hash failed", str(exc))
        raise click.Abort()

    table = Table(title=f"Hashes — {target.name}", box=None, show_edge=False)
    table.add_column("Algorithm", style="bold cyan", min_width=10)
    table.add_column("Digest", style="white")

    for algo, digest in result.hashes.items():
        table.add_row(algo.upper(), digest)

    table.add_section()
    table.add_row("[dim]Size (bytes)[/dim]", str(result.size_bytes))

    console.print(table)


# ---------------------------------------------------------------------------
# identify
# ---------------------------------------------------------------------------


@cli.command("identify")
@click.argument("file", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--no-table", is_flag=True, help="Print raw values instead of a Rich table.")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Output identification result as JSON.",
)
def identify_cmd(file: Path, no_table: bool, as_json: bool) -> None:
    """Identify file type using libmagic and magic bytes.

    \b
    Examples:
      rft identify suspicious.bin
      rft identify suspicious.bin --json
    """
    # --- Lazy imports ---
    import json as _json

    from core.logger import LoggerManager
    from utils.file_identifier import FileIdentifier

    console = Console()
    logger = LoggerManager().get_logger("rf_tools.cli")

    target = _validate_file(console, file)
    if target is None:
        raise click.Abort()

    try:
        identifier = FileIdentifier(console=console)
    except RuntimeError as exc:
        _print_error(
            console,
            "libmagic not available",
            f"{exc}\n\n[dim]Install: sudo apt install libmagic1[/dim]",
        )
        raise click.Abort()

    try:
        result = identifier.identify(
            target,
            show_table=(not no_table and not as_json),
        )
    except PermissionError as exc:
        _print_error(console, "Permission denied", str(exc))
        raise click.Abort()
    except FileNotFoundError as exc:
        _print_error(console, "File not found", str(exc))
        raise click.Abort()
    except Exception as exc:
        logger.exception("identify command failed")
        _print_error(console, "Identify failed", str(exc))
        raise click.Abort()

    if as_json:
        console.print(
            _json.dumps(FileIdentifier.to_dict(result), indent=2)
        )


# ---------------------------------------------------------------------------
# hexdump
# ---------------------------------------------------------------------------


@cli.command("hexdump")
@click.argument("file", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option(
    "--bytes",
    "bytes_per_line",
    default=None,
    type=int,
    help="Bytes displayed per line (default: 16 from config).",
)
@click.option(
    "--lines",
    "max_lines",
    default=None,
    type=int,
    help="Maximum lines to display (default: 200 from config).",
)
@click.option(
    "--output",
    default=None,
    type=str,
    help="Save dump to data/output/<OUTPUT> instead of displaying.",
)
def hexdump_cmd(
    file: Path,
    bytes_per_line: Optional[int],
    max_lines: Optional[int],
    output: Optional[str],
) -> None:
    """Display or export a hex dump of FILE.

    \b
    Examples:
      rft hexdump malware.exe
      rft hexdump malware.exe --bytes 32 --lines 50
      rft hexdump malware.exe --output dump.txt
    """
    # --- Lazy imports ---
    from core.logger import LoggerManager
    from utils.hex_dump_viewer import HexDumpConfig, HexDumpViewer

    console = Console()
    logger = LoggerManager().get_logger("rf_tools.cli")
    viewer = HexDumpViewer(console=console)

    target = _validate_file(console, file)
    if target is None:
        raise click.Abort()

    # Build config override only when the user explicitly passed options.
    config: Optional[HexDumpConfig] = None
    if bytes_per_line is not None or max_lines is not None:
        default_cfg = viewer._load_default_config()
        config = HexDumpConfig(
            bytes_per_line=bytes_per_line if bytes_per_line is not None else default_cfg.bytes_per_line,
            offset_width=default_cfg.offset_width,
            max_lines=max_lines if max_lines is not None else default_cfg.max_lines,
        )

    try:
        if output:
            summary = viewer.save_dump(
                target,
                output_filename=output,
                config=config,
            )
            console.print(f"[green]Saved:[/green] {summary.export_path}")
            if summary.truncated:
                console.print(
                    f"[yellow]Warning:[/yellow] Output truncated "
                    f"({summary.total_lines} total lines, "
                    f"{summary.bytes_per_line} bytes/line)."
                )
        else:
            truncated = viewer.display_dump(
                target,
                config=config,
                show_panel=True,
                title=f"Hex Dump — {target.name}",
            )
            if truncated:
                console.print(
                    "[yellow]Warning:[/yellow] Display truncated. "
                    "Use [bold]--lines N[/bold] or [bold]--output FILE[/bold] for full dump."
                )

    except ValueError as exc:
        _print_error(console, "Invalid argument", str(exc))
        raise click.Abort()
    except PermissionError as exc:
        _print_error(console, "Permission denied", str(exc))
        raise click.Abort()
    except Exception as exc:
        logger.exception("hexdump command failed")
        _print_error(console, "Hexdump failed", str(exc))
        raise click.Abort()


# ---------------------------------------------------------------------------
# pe (implemented in separate module)
# ---------------------------------------------------------------------------


# Import-time wiring only; the command itself lives in cli_pe.py.
from reverse_engineering.binary_analysis.cli_pe import pe_cmd  # noqa: E402,F401

cli.add_command(pe_cmd)


# ---------------------------------------------------------------------------
# elf  (placeholder)
# ---------------------------------------------------------------------------



@cli.command("elf")
@click.argument("file", type=click.Path(exists=False, dir_okay=False, path_type=Path))
def elf_cmd(file: Path) -> None:
    """Analyze an ELF binary. [coming soon]

    \b
    Planned features:
      sections, symbols, dynamic deps, security mitigations
    """
    console = Console()
    target = _validate_file(console, file)
    if target is None:
        raise click.Abort()
    _print_coming_soon(console, "ELF")


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


@cli.command("version")
def version_cmd() -> None:
    """Show version and build information."""
    console = Console()
    console.print(
        Panel(
            "[bold cyan]reverse-forensic-tools[/bold cyan] [bold]v1.0.0[/bold]\n"
            "[dim]Python:[/dim] "
            f"[white]{sys.version.split()[0]}[/white]\n"
            "[dim]Author:[/dim] [white]Operator Cedra[/white]\n"
            "[dim]License:[/dim] [white]MIT[/white]",
            border_style="cyan",
            padding=(1, 2),
        )
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main() -> None:
    """Console script entrypoint — registered as `rft` in pyproject.toml."""
    console = Console()

    # Print banner only when help is explicitly requested, not on every run.
    if any(a in ("--help", "-h") for a in sys.argv[1:]) or len(sys.argv) == 1:
        console.print(
            Panel.fit(
                f"[bold cyan]{ASCII_BANNER}[/bold cyan]\n"
                "[bold white]Operator Cedra[/bold white]  "
                "[dim]|[/dim]  "
                "[bold]Reverse Forensic Tools[/bold]",
                title="[bold blue]Operator Cedra[/bold blue]",
                subtitle="[dim]Nous frappons dans l'ombre pour protéger la lumière.[/dim]",
                border_style="blue",
                padding=(1, 2),
            )
        )

    cli(standalone_mode=True)


if __name__ == "__main__":
    main()
