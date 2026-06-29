from __future__ import annotations

import json
from pathlib import Path

try:
    import click  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    raise SystemExit("Missing dependency: click. Install with `pip install -e .`")

from rich.console import Console
from rich.panel import Panel

from core.logger import LoggerManager
from reverse_engineering.binary_analysis.pe_parser import PEAnalyzer


def _color_for_anomaly(msg: str) -> str:
    lowered = msg.lower()
    if any(
        key in lowered
        for key in (
            "suspicious",
            "violation",
            "packed",
            "encrypted",
            "w^x",
            "no imports",
            "mismatched",
        )
    ):
        return "red"
    if any(key in lowered for key in ("warning", "non-standard", "non standard")):
        return "yellow"
    return "green"


@click.command("pe")
@click.argument("file", type=click.Path(exists=False, dir_okay=False, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output JSON only.")
@click.option("--sections", is_flag=True, help="Show only section analysis.")
@click.option("--imports", "show_imports", is_flag=True, help="Show only import analysis.")
@click.option("--exports", "show_exports", is_flag=True, help="Show only export analysis.")
@click.option(
    "--full",
    "show_full",
    is_flag=True,
    help="Show full Rich report (default when no other flags are provided).",
)
def pe_cmd(
    file: Path,
    as_json: bool,
    sections: bool,
    show_imports: bool,
    show_exports: bool,
    show_full: bool,
) -> None:
    """Analyze a PE (Portable Executable) binary."""

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

    analyzer = PEAnalyzer()

    # Default selection: full unless user explicitly chose a subset.
    any_subset = any([sections, show_imports, show_exports])
    if not any_subset and not show_full:
        show_full = True

    try:
        if as_json:
            report = analyzer.generate_report(file, options={
                "sections": sections,
                "imports": show_imports,
                "exports": show_exports,
                "full": show_full,
                "json": True,
            })
            console.print(json.dumps(report, indent=2))
            return

        # Rich output
        analyzer.generate_report(
            file,
            options={
                "sections": sections,
                "imports": show_imports,
                "exports": show_exports,
                "full": show_full,
                "json": False,
                "console": console,
            },
        )

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
        logger.exception("pe command failed")
        console.print(Panel(str(exc), title="[red]PE analysis failed[/red]", border_style="red"))
        raise click.Abort()

