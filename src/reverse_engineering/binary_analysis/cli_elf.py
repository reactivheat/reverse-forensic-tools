from __future__ import annotations

import json
import os
from pathlib import Path

try:
    import click  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    raise SystemExit("Missing dependency: click. Install with `pip install -e .`")

from rich.console import Console
from rich.panel import Panel

from core.logger import LoggerManager
from reverse_engineering.binary_analysis.elf_parser import ELFParser


@click.command("elf")
@click.argument("file", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output JSON only.")
@click.option(
    "--output",
    default=None,
    type=str,
    help="Save summary as JSON under results/<output> instead of printing.",
)
def elf_cmd(file: Path, as_json: bool, output: str | None) -> None:
    """Analyze an ELF binary.

    \b
    Examples:
      rft elf sample.bin
      rft elf sample.bin --json
      rft elf sample.bin --output sample_elf.json
    """

    console = Console()
    logger = LoggerManager().get_logger("rf_tools.cli")

    if not file.exists():
        console.print(Panel(f"File not found: {file}", title="[red]Error[/red]", border_style="red"))
        raise click.Abort()
    if not file.is_file():
        console.print(
            Panel(
                f"Invalid input (not a file): {file}",
                title="[red]Error[/red]",
                border_style="red",
            )
        )
        raise click.Abort()

    # ELFParser.parse() prints a Rich "Hashes" panel as a side effect.
    # For --json/--output we want clean, script-friendly output, so we
    # give it a silent console for parsing and only print explicitly below.
    quiet_console = Console(file=open(os.devnull, "w"))
    parser = ELFParser(file, console=quiet_console if (as_json or output) else console)

    try:
        if output:
            saved_path = parser.save_json(output)
            console.print(f"[green]Saved:[/green] {saved_path}")
            return

        if as_json:
            console.print(json.dumps(parser.summary(), indent=2, sort_keys=True))
            return

        parser.display()

    except ValueError as exc:
        console.print(Panel(str(exc), title="[red]Error[/red]", border_style="red"))
        raise click.Abort()
    except PermissionError as exc:
        console.print(Panel(str(exc), title="[red]Permission denied[/red]", border_style="red"))
        raise click.Abort()
    except FileNotFoundError as exc:
        console.print(Panel(str(exc), title="[red]File not found[/red]", border_style="red"))
        raise click.Abort()
    except Exception as exc:
        logger.exception("elf command failed")
        console.print(Panel(str(exc), title="[red]ELF analysis failed[/red]", border_style="red"))
        raise click.Abort()
