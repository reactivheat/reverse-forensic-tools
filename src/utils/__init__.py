"""Utility subpackage for Reverse Forensic Tools.

This module exposes the public API of utilities.
"""

from utils.hash_calculator import HashCalculator, HashResult
from utils.hex_dump_viewer import HexDumpConfig, HexDumpSummary, HexDumpViewer

# FileIdentifier is imported from utils.file_identifier directly so importing
# this package does not require python-magic/libmagic at package-import time.
__all__ = [
    "HashCalculator",
    "HashResult",
    "HexDumpConfig",
    "HexDumpSummary",
    "HexDumpViewer",
]

