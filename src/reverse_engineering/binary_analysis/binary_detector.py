from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.logger import setup_logger
from core.config_manager import ConfigManager
from utils.file_identifier import FileIdentifier


@dataclass(frozen=True)
class DetectedBinary:
    """Result of binary detection."""

    kind: str
    confidence: float
    mime_type: Optional[str]
    extension_hint: Optional[str]


class BinaryDetector:
    """Detect binary format type (PE/ELF/Mach-O/Unknown).

    Detection strategy (fast, best-effort):
      - MIME from libmagic when available (FileIdentifier)
      - Magic-bytes heuristics as fallback

    This class is intended to be used before invoking specific parsers.
    """

    def __init__(self) -> None:
        """Initialize the detector."""

        self._logger = setup_logger(name="rf_tools.binary_detector")
        self._config = ConfigManager()
        self._file_identifier = FileIdentifier()

    @staticmethod
    def _read_magic_bytes(path: Path, n: int = 16) -> bytes:
        """Read the first n bytes safely."""
        with path.open("rb") as f:
            return f.read(n)

    @staticmethod
    def _detect_by_magic(magic_bytes: bytes) -> DetectedBinary:
        """Detect by magic bytes heuristics."""

        # PE: starts with 'MZ'
        if len(magic_bytes) >= 2 and magic_bytes[:2] == b"MZ":
            return DetectedBinary(kind="PE", confidence=0.95, mime_type=None, extension_hint=None)

        # ELF: 0x7f 'E' 'L' 'F'
        if len(magic_bytes) >= 4 and magic_bytes[:4] == b"\x7fELF":
            return DetectedBinary(kind="ELF", confidence=0.95, mime_type=None, extension_hint=None)

        # Mach-O magic values (big/little + 32/64)
        # https://en.wikipedia.org/wiki/Mach-O
        if len(magic_bytes) >= 4:
            m = int.from_bytes(magic_bytes[:4], byteorder="big", signed=False)
            l = int.from_bytes(magic_bytes[:4], byteorder="little", signed=False)
            mach_magics = {
                0xFEEDFACE,
                0xCEFAEDFE,
                0xFEEDFACF,
                0xCFFAEDFE,
            }
            # For FAT binaries/universal:
            fat_magics = {0xCAFEBABE, 0xBEBAFECA}
            if m in mach_magics or l in mach_magics or m in fat_magics or l in fat_magics:
                return DetectedBinary(kind="Mach-O", confidence=0.9, mime_type=None, extension_hint=None)

        return DetectedBinary(kind="Unknown", confidence=0.0, mime_type=None, extension_hint=None)

    def detect(self, file_path: Path) -> DetectedBinary:
        """Detect the binary type.

        Args:
            file_path: Target file.

        Returns:
            DetectedBinary result.

        Raises:
            FileNotFoundError: If file_path does not exist.
            IsADirectoryError: If file_path is a directory.
            PermissionError: If file cannot be read.
            OSError: For other I/O errors.
        """

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {file_path}")

        target = file_path.expanduser().resolve()

        mime_type: Optional[str] = None
        extension_hint: Optional[str] = target.suffix.lstrip(".").lower() or None

        # libmagic (best-effort)
        try:
            ident = self._file_identifier.identify(target, show_table=False)
            mime_type = ident.mime_type
        except Exception as exc:
            self._logger.debug("libmagic detection failed: %s", exc)

        # magic bytes (authoritative for most common cases)
        magic_bytes = self._read_magic_bytes(target, n=16)
        detected = self._detect_by_magic(magic_bytes)

        # If libmagic suggests PE/ELF/Mach-O, boost confidence.
        if mime_type:
            m_low = mime_type.lower()
            if "windows" in m_low or "pe32" in m_low or "pe" in m_low:
                if detected.kind != "PE":
                    detected = DetectedBinary(kind="PE", confidence=max(detected.confidence, 0.75), mime_type=mime_type, extension_hint=extension_hint)
                else:
                    detected = DetectedBinary(kind="PE", confidence=max(detected.confidence, 0.95), mime_type=mime_type, extension_hint=extension_hint)
            elif "elf" in m_low:
                if detected.kind != "ELF":
                    detected = DetectedBinary(kind="ELF", confidence=max(detected.confidence, 0.75), mime_type=mime_type, extension_hint=extension_hint)
                else:
                    detected = DetectedBinary(kind="ELF", confidence=max(detected.confidence, 0.95), mime_type=mime_type, extension_hint=extension_hint)
            elif "mach-o" in m_low or "os x" in m_low or "darwin" in m_low:
                if detected.kind != "Mach-O":
                    detected = DetectedBinary(kind="Mach-O", confidence=max(detected.confidence, 0.7), mime_type=mime_type, extension_hint=extension_hint)
                else:
                    detected = DetectedBinary(kind="Mach-O", confidence=max(detected.confidence, 0.9), mime_type=mime_type, extension_hint=extension_hint)

        # Attach mime/extension info if not already
        if detected.mime_type is None:
            detected = DetectedBinary(
                kind=detected.kind,
                confidence=detected.confidence,
                mime_type=mime_type,
                extension_hint=extension_hint,
            )

        return detected

