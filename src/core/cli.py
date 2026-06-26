from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel

from core.config_manager import ConfigManager
from core.logger import LoggerManager
from utils import FileIdentifier, HashCalculator, HexDumpViewer, HexDumpConfig



class ReverseForensicCLI:
    """Main CLI entrypoint for Reverse Forensic Tools."""

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize the CLI.

        Args:
            console: Optional Rich console.
        """

        self._console = console or Console()
        self._config = ConfigManager()
        self._logger = LoggerManager().get_logger("rf_tools.cli")
        self._hash = HashCalculator(console=self._console)
        self._identifier = FileIdentifier(console=self._console)
        self._hexdump = HexDumpViewer(console=self._console)

    def print_banner(self) -> None:
        """Print the application banner."""

        ascii_art = (
            " ██████╗███████╗██████╗ ██████╗  █████╗\n"
            "██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗\n"
            "██║     █████╗  ██║  ██║██████╔╝███████║\n"
            "██║     ██╔══╝  ██║  ██║██╔══██╗██╔══██║\n"
            "╚██████╗███████╗██████╔╝██║  ██║ ██║  ██║\n"
            " ╚═════╝╚══════╝╚═════╝ ╚═╝  ╚═╝  ╚═╝  ╚═╝\n"
        )

        banner = Panel.fit(
            f"[bold cyan]{ascii_art}[/bold cyan]\n\n"
            f"[bold]Operator Cedra[/bold]\n"
            f"[bold]Reverse Forensic Tools[/bold]\n",
            title="[bold]Operator Cedra[/bold]",
            subtitle="Stand by Rules",
            border_style="blue",
            padding=(1, 2),
        )
        self._console.print(banner)

    def build_parser(self) -> argparse.ArgumentParser:
        """Build the CLI argument parser."""

        parser = argparse.ArgumentParser(
            prog="rf-tools",
            description="Reverse Forensic Tools - Operator Cedra",
        )
        parser.add_argument(
            "--no-banner",
            action="store_true",
            help="Do not show the banner.",
        )

        subparsers = parser.add_subparsers(dest="command", required=True)

        # hash
        p_hash = subparsers.add_parser("hash", help="Compute file hashes")
        p_hash.add_argument("path", type=str, help="Path to the input file")
        p_hash.add_argument(
            "--algos",
            type=str,
            default=None,
            help="Comma-separated algorithms (e.g., sha256,sha1,md5)",
        )
        p_hash.add_argument(
            "--chunk-size",
            type=int,
            default=1024 * 1024,
            help="Read chunk size in bytes",
        )
        p_hash.add_argument(
            "--no-progress",
            action="store_true",
            help="Disable progress bar.",
        )

        # identify
        p_ident = subparsers.add_parser(
            "identify", help="Identify file type (libmagic + bytes)"
        )
        p_ident.add_argument("path", type=str, help="Path to the input file")
        p_ident.add_argument(
            "--no-table",
            action="store_true",
            help="Disable Rich table output.",
        )

        # hexdump
        p_hex = subparsers.add_parser("hexdump", help="Render and save hex dump")
        p_hex.add_argument("path", type=str, help="Path to the input file")
        p_hex.add_argument(
            "--output",
            type=str,
            default=None,
            help="Output filename to write under data/output/",
        )
        p_hex.add_argument(
            "--bytes-per-line",
            type=int,
            default=None,
            help="Bytes per line (overrides config).",
        )
        p_hex.add_argument(
            "--offset-width",
            type=int,
            default=None,
            help="Offset width in hex digits (overrides config).",
        )
        p_hex.add_argument(
            "--max-lines",
            type=int,
            default=None,
            help="Maximum lines to render/export (overrides config).",
        )
        p_hex.add_argument(
            "--no-panel",
            action="store_true",
            help="Disable Rich panel wrapper.",
        )
        p_hex.add_argument(
            "--export-lines",
            type=int,
            default=None,
            help="Maximum lines to export when output is set.",
        )

        return parser

    def handle_hash(self, args: argparse.Namespace) -> int:
        """Handle the hash command."""

        path = Path(args.path)
        if not path.exists():
            self._console.print(f"[bold red]File not found:[/bold red] {path}")
            return 2

        algos = None
        if args.algos:
            algos = [a.strip() for a in args.algos.split(",") if a.strip()]

        try:
            result = self._hash.compute_hashes(
                path,
                algorithms=algos
                if algos
                else self._config.get(
                    "hash.algorithms", ["md5", "sha1", "sha256"]
                ),
                chunk_size=args.chunk_size,
                show_progress=not args.no_progress,
            )
        except Exception as exc:  # pragma: no cover
            self._console.print(f"[bold red]Hash failed:[/bold red] {exc}")
            self._logger.exception("hash command failed")
            return 1

        for algo, digest in result.hashes.items():
            self._console.print(f"[cyan]{algo}[/cyan]: {digest}")
        return 0

    def handle_identify(self, args: argparse.Namespace) -> int:
        """Handle the identify command."""

        path = Path(args.path)
        if not path.exists():
            self._console.print(f"[bold red]File not found:[/bold red] {path}")
            return 2

        try:
            self._identifier.identify(path, show_table=not args.no_table)
        except Exception as exc:  # pragma: no cover
            self._console.print(f"[bold red]Identify failed:[/bold red] {exc}")
            self._logger.exception("identify command failed")
            return 1
        return 0

    def handle_hexdump(self, args: argparse.Namespace) -> int:
        """Handle the hexdump command."""

        # HexDumpConfig is part of the public utils API.
        from utils import HexDumpConfig




        path = Path(args.path)
        if not path.exists():
            self._console.print(f"[bold red]File not found:[/bold red] {path}")
            return 2

        config = None
        if (
            args.bytes_per_line is not None
            or args.offset_width is not None
            or args.max_lines is not None
        ):
            # Read defaults from config/config.yaml via viewer.
            default_config = self._hexdump._load_default_config()

            config = HexDumpConfig(
                bytes_per_line=args.bytes_per_line
                if args.bytes_per_line is not None
                else default_config.bytes_per_line,
                offset_width=args.offset_width
                if args.offset_width is not None
                else default_config.offset_width,
                max_lines=args.max_lines
                if args.max_lines is not None
                else default_config.max_lines,
            )

        try:
            truncated = self._hexdump.display_dump(
                path,
                config=config,
                show_panel=not args.no_panel,
            )
            if args.output:
                summary = self._hexdump.save_dump(
                    path,
                    output_filename=args.output,
                    config=config,
                    export_lines=args.export_lines,
                )
                self._console.print(
                    f"[green]Saved:[/green] {summary.export_path}"
                )
                if summary.truncated:
                    self._console.print(
                        "[yellow]Warning:[/yellow] Export was truncated."
                    )
                return 0

            if truncated:
                self._console.print(
                    "[yellow]Warning:[/yellow] Display output was truncated."
                )
            return 0
        except Exception as exc:  # pragma: no cover
            self._console.print(f"[bold red]Hexdump failed:[/bold red] {exc}")
            self._logger.exception("hexdump command failed")
            return 1

    def run(self, argv: Optional[list[str]] = None) -> int:
        """Run the CLI."""

        parser = self.build_parser()
        args = parser.parse_args(argv)

        if not getattr(args, "no_banner", False):
            self.print_banner()

        command = str(args.command)
        if command == "hash":
            return self.handle_hash(args)
        if command == "identify":
            return self.handle_identify(args)
        if command == "hexdump":
            return self.handle_hexdump(args)

        self._console.print(f"[bold red]Unknown command:[/bold red] {command}")
        return 2


def main() -> None:
    """Entry point for rf-tools console script."""

    cli = ReverseForensicCLI()
    code = cli.run()
    raise SystemExit(code)

