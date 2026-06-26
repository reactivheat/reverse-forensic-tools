import json
from pathlib import Path

import pytest

from src.utils.hex_dump_viewer import HexDumpViewer, HexDumpConfig


@pytest.mark.parametrize("bytes_per_line", [1, 8, 16])
def test_hex_dump_viewer_render_limits_lines(tmp_path: Path, bytes_per_line: int) -> None:
    sample = tmp_path / "sample.bin"
    data = bytes(range(0, 64))
    sample.write_bytes(data)

    config = HexDumpConfig(bytes_per_line=bytes_per_line, max_lines=3, offset_width=4)
    viewer = HexDumpViewer(console=None)

    # Should not raise.
    viewer.render(sample, config=config, show_panel=False)


def test_hex_dump_export_restricts_output_folder(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abc123")

    viewer = HexDumpViewer(console=None)

    # Export with a name is allowed; it should land in data/output.
    exported = viewer.export(sample, "dump.txt", config=HexDumpConfig(max_lines=1))
    assert exported.exists()
    assert "data" in str(exported)
    assert str(exported).replace("\\", "/").endswith("/data/output/dump.txt")

