import json
import platform
import shutil
import subprocess
from pathlib import Path

import pytest

from reverse_engineering.binary_analysis.elf_parser import ELFInfo, ELFParser, ELFSecurityMitigations


COMPILER = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")

SOURCE = r"""
#include <stdio.h>

__attribute__((noinline)) int print_message(const char *input) {
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s", input);
    return puts(buffer);
}

int main(int argc, char **argv) {
    return print_message(argc > 1 ? argv[1] : "ok") == EOF;
}
"""


def build_elf(tmp_path: Path, name: str, *flags: str) -> Path:
    if platform.system() != "Linux" or COMPILER is None:
        pytest.skip("ELF mitigation tests require a Linux C compiler")

    source = tmp_path / f"{name}.c"
    binary = tmp_path / name
    source.write_text(SOURCE, encoding="utf-8")
    try:
        subprocess.run(
            [COMPILER, *flags, str(source), "-o", str(binary)],
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        pytest.skip(f"compiler could not build requested ELF: {exc.stderr}")
    return binary


def parse_mitigations(binary: Path) -> ELFSecurityMitigations:
    parser = ELFParser(binary)
    parser.parse()
    assert parser._info is not None
    return parser._info.security_mitigations


def test_elf_parser_detects_nx_enabled_and_disabled(tmp_path: Path) -> None:
    nx_enabled = build_elf(tmp_path, "nx-enabled", "-Wl,-z,noexecstack")
    nx_disabled = build_elf(tmp_path, "nx-disabled", "-Wl,-z,execstack")

    assert parse_mitigations(nx_enabled).nx is True
    assert parse_mitigations(nx_disabled).nx is False


def test_elf_parser_distinguishes_pie_from_plain_shared_library(tmp_path: Path) -> None:
    pie = build_elf(tmp_path, "pie", "-fPIE", "-pie")
    shared = build_elf(tmp_path, "plain-shared.so", "-shared", "-fPIC")

    assert parse_mitigations(pie).pie is True
    assert parse_mitigations(shared).pie is False


def test_elf_parser_detects_none_partial_and_full_relro(tmp_path: Path) -> None:
    relro_none = build_elf(tmp_path, "relro-none", "-Wl,-z,norelro")
    relro_partial = build_elf(tmp_path, "relro-partial", "-Wl,-z,relro")
    relro_full = build_elf(tmp_path, "relro-full", "-Wl,-z,relro,-z,now")

    assert parse_mitigations(relro_none).relro == "None"
    assert parse_mitigations(relro_partial).relro == "Partial"
    assert parse_mitigations(relro_full).relro == "Full"


def test_elf_parser_detects_stack_canary_and_fortify_source(tmp_path: Path) -> None:
    protected = build_elf(
        tmp_path,
        "protected",
        "-O2",
        "-D_FORTIFY_SOURCE=2",
        "-fstack-protector-all",
    )
    unprotected = build_elf(
        tmp_path,
        "unprotected",
        "-O0",
        "-U_FORTIFY_SOURCE",
        "-D_FORTIFY_SOURCE=0",
        "-fno-stack-protector",
    )

    protected_mitigations = parse_mitigations(protected)
    unprotected_mitigations = parse_mitigations(unprotected)

    assert protected_mitigations.stack_canary is True
    assert protected_mitigations.fortify_source is True
    assert unprotected_mitigations.stack_canary is False
    assert unprotected_mitigations.fortify_source is False


def test_elf_security_mitigations_round_trip_through_info_and_json(tmp_path: Path) -> None:
    binary = build_elf(
        tmp_path,
        "round-trip",
        "-O2",
        "-D_FORTIFY_SOURCE=2",
        "-fstack-protector-all",
        "-Wl,-z,relro,-z,now",
    )
    parser = ELFParser(binary)
    parser.parse()

    assert parser._info is not None
    expected = parser._info.security_mitigations.to_dict()
    assert parser._info.to_dict()["security_mitigations"] == expected
    assert parser.summary()["security_mitigations"] == expected
    assert json.loads(parser.to_json())["security_mitigations"] == expected


def test_elf_parser_rejects_malformed_file(tmp_path: Path) -> None:
    malformed = tmp_path / "truncated.elf"
    malformed.write_bytes(b"\x7fELF")

    with pytest.raises(ValueError):
        ELFParser(malformed).parse()