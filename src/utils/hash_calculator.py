from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

from rich.console import Console
from rich.progress import BarColumn, Progress, TaskID, TextColumn, TimeElapsedColumn


@dataclass(frozen=True)
class HashResult:
    """Result of hashing a file."""

    path: Path
    size_bytes: int
    hashes: Dict[str, str]


class HashCalculator:
    """Compute cryptographic hashes for files."""

    DEFAULT_ALGORITHMS: Iterable[str] = ("sha256", "sha1", "md5")

    def __init__(self, console: Optional[Console] = None) -> None:
        """Initialize the calculator.

        Args:
            console: Optional Rich console.
        """

        self._console = console or Console()

    @staticmethod
    def _validate_path(file_path: Path) -> None:
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        if not file_path.is_file():
            raise IsADirectoryError(f"Path is not a file: {file_path}")

    @staticmethod
    def _normalize_algorithms(algorithms: Iterable[str]) -> list[str]:
        normalized: list[str] = []
        for algo in algorithms:
            algo_norm = str(algo).strip().lower()
            if not algo_norm:
                continue
            try:
                hashlib.new(algo_norm)
            except ValueError as exc:
                raise ValueError(f"Unsupported hash algorithm: {algo_norm}") from exc
            normalized.append(algo_norm)
        if not normalized:
            raise ValueError("At least one hashing algorithm must be provided.")
        return normalized

    def compute_hashes(
        self,
        file_path: Path,
        algorithms: Iterable[str] = DEFAULT_ALGORITHMS,
        chunk_size: int = 1024 * 1024,
        show_progress: bool = True,
    ) -> HashResult:
        """Compute hashes for a file.

        Args:
            file_path: File to hash.
            algorithms: Iterable of hashlib algorithm names.
            chunk_size: Bytes per read.
            show_progress: Whether to display a Rich progress bar.

        Returns:
            HashResult containing file metadata and computed digests.

        Raises:
            FileNotFoundError: If file does not exist.
            IsADirectoryError: If path is a directory.
            ValueError: If algorithms are invalid.
            PermissionError: If file cannot be read due to permissions.
            OSError: If reading fails.
        """

        if chunk_size <= 0:
            raise ValueError("chunk_size must be > 0")

        target = file_path.expanduser().resolve()
        self._validate_path(target)
        algos = self._normalize_algorithms(algorithms)

        size_bytes = target.stat().st_size
        hash_objs: Dict[str, "hashlib._Hash"] = {
            algo: hashlib.new(algo) for algo in algos
        }

        progress: Optional[Progress] = None
        task_id: Optional[TaskID] = None

        try:
            if show_progress:
                progress = Progress(
                    TextColumn("[progress.description]{task.description}"),
                    "[progress.percentage]{task.percentage:>3.0f}%",
                    BarColumn(),
                    "•",
                    TimeElapsedColumn(),
                )
                task_id = progress.add_task("Hashing", total=size_bytes)

            if progress is not None:
                with progress:
                    self._console.print(f"Computing hashes: {target}")
                    with target.open("rb") as f:
                        while True:
                            chunk = f.read(chunk_size)
                            if not chunk:
                                break
                            for hasher in hash_objs.values():
                                hasher.update(chunk)
                            if task_id is not None:
                                progress.update(task_id, advance=len(chunk))
            else:
                with target.open("rb") as f:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk:
                            break
                        for hasher in hash_objs.values():
                            hasher.update(chunk)

        except PermissionError as exc:
            raise PermissionError(f"Permission denied while reading: {target}") from exc
        except OSError as exc:
            raise OSError(f"Failed to read file for hashing: {target}") from exc

        digests = {algo: obj.hexdigest() for algo, obj in hash_objs.items()}
        return HashResult(path=target, size_bytes=size_bytes, hashes=digests)

