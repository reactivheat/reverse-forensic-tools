<p align="center">
  <img src="docs/images/bannerforen.png" alt="Reverse Forensic Tools Banner" width="100%">
</p>

<h1 align="center">reverse-forensic-tools</h1>

<p align="center">
 <img alt="CI" src="https://github.com/reactivheat/reverse-forensic-tools/actions/workflows/ci.yml/badge.svg" />

  <img alt="Python 3.12+" src="https://img.shields.io/badge/Python-3.12%2B-blue" />
  <img alt="License MIT" src="https://img.shields.io/badge/License-MIT-red" />
  <img alt="Platform Linux" src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-green" />
  <img alt="Open Source" src="https://img.shields.io/badge/Open%20Source-Yes-success" />
</p>

---

## About

**reverse-forensic-tools** adalah production-grade CLI toolkit berbasis Python untuk **Reverse Engineering, Digital Forensics, Incident Response (DFIR), dan Malware Analysis**. Dirancang untuk mempercepat workflow analisis artefak binary — mulai dari kalkulasi hash dan identifikasi tipe file, hingga pemeriksaan struktur PE/ELF dan deteksi indikasi aktivitas berbahaya.

Dibangun untuk SOC Analysts, DFIR Investigators, malware researchers, dan security students yang membutuhkan tooling yang cepat, modular, dan dapat diandalkan dalam satu framework terpadu. Semua output menggunakan Rich terminal rendering untuk mempercepat proses triase dan review.

Dibuat oleh **Operator Cedra** — *"Nous frappons dans l'ombre pour protéger la lumière."*

---

## Features

| Feature | Status |
|---|---|
| Hash Calculator | ✅ Done |
| File Identifier | ✅ Done |
| Hex Dump Viewer | ✅ Done |
| PE Analyzer | ✅ Done |
| ELF Analyzer | 🚧 WIP |
| Disassembler | ⏳ Planned |
| Malware Analysis | ⏳ Planned |
| Memory Forensics | ⏳ Planned |
| Disk Forensics | ⏳ Planned |
| Network Forensics | ⏳ Planned |
| Log Analysis | ⏳ Planned |

---

## Prerequisites

- **Python 3.12+**
- **pip** / **virtualenv**
- **libmagic**
  - Linux/Parrot OS: `sudo apt install libmagic1`
  - Windows (dev only): `pip install python-magic-bin`
- **pefile** — auto-installed via `pip install -e .`
- **Optional (Phase 3)**: Volatility3 (memory forensics)

---

## Installation

```bash
git clone https://github.com/reactivheat/reverse-forensic-tools.git
cd reverse-forensic-tools

python -m venv .venv

# Linux / Parrot OS:
source .venv/bin/activate

# Windows (dev):
# .venv\Scripts\activate

pip install -e .
pip install pefile rich click pyyaml
```

---

## Quick Start

### Help & available commands

```bash
rft --help
```

```
 ██████╗███████╗██████╗ ██████╗  █████╗
██╔════╝██╔════╝██╔══██╗██╔══██╗██╔══██╗
██║     █████╗  ██║  ██║██████╔╝███████║
██║     ██╔══╝  ██║  ██║██╔══██╗██╔══██║
╚██████╗███████╗██████╔╝██║  ██║██║  ██║
 ╚═════╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝

Operator Cedra  |  Reverse Forensic Tools

Commands:
  elf       Analyze an ELF binary.
  hash      Compute cryptographic hashes for FILE.
  hexdump   Display or export a hex dump of FILE.
  identify  Identify file type using libmagic and magic bytes.
  pe        Analyze a PE (Portable Executable) binary.
  version   Show version and build information.
```

### Hash a file

```bash
rft hash malware.exe --no-progress
```

```
         Hashes — malware.exe
 Algorithm  Digest
 MD5        9e60393da455f93b0ec32cf124432651
 SHA1       633fd6744b1d1d9ad5d46f8e648209bfdfb0c573
 SHA256     84b484fd3636f2ca3e468d2821d97aacde8a143a2724a3ae65f48a33ca2fd258
 ─────────────────────────────────────────────────────────────
 Size (bytes)  360448
```

### Identify file type

```bash
rft identify malware.exe
```

```
        File Identification
 Field        Value
 Path         /samples/malware.exe
 Size         360448
 MIME         application/x-dosexec
 Description  PE32+ executable (GUI) x86-64, for MS Windows
 Magic Bytes  4d5a90000300000004000000ffff0000
```

### Hex dump

```bash
rft hexdump malware.exe --bytes 16 --lines 8
```

```
╭──── Hex Dump — malware.exe ────╮
│ Offset    Hex                                       ASCII           │
│ 00000000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00  MZ...... │
│ 00000010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........  │
│ 00000020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ........  │
╰────────────────────────────────────────────────────────────────────╯
```

### PE analysis

```bash
rft pe malware.exe --full
```

```
╭──────────────────── Metadata ────────────────────╮
│ MD5              9e60393da455f93b0ec32cf124432651 │
│ SHA256           84b484fd3636f2ca3ae65f48a33ca2fd │
│ Compile timestamp  2036-03-01 22:37:00 UTC        │
│ Machine type     x64                              │
│ Subsystem        GUI                              │
│ Entry point      0x19b0                           │
│ Image base       0x140000000                      │
│ # Sections       8                                │
╰──────────────────────────────────────────────────╯

╭────── Sections ──────╮
│ .text   entropy 6.23  R/X  ✅ clean     │
│ .rdata  entropy 5.55  R    ✅ clean     │
│ .rsrc   entropy 6.96  R    ⚠️ high      │
│ fothk   entropy 0.01  R/X  🔴 anomaly  │
╰──────────────────────╯

╭──── Anomalies ────╮
│ Non-standard section name: fothk  │
│ Non-standard section name: .pdata │
╰───────────────────╯
```

---

## Command Reference

| Command | Description | Key Options |
|---|---|---|
| `rft hash <file>` | Compute cryptographic hashes | `--algos sha256,md5`, `--no-progress` |
| `rft identify <file>` | Identify file type via libmagic | `--json`, `--no-table` |
| `rft hexdump <file>` | Hex dump viewer | `--bytes N`, `--lines N`, `--output FILE` |
| `rft pe <file>` | PE binary analyzer | `--full`, `--sections`, `--imports`, `--exports`, `--json` |
| `rft elf <file>` | ELF binary analyzer | coming soon |
| `rft version` | Show version and build info | — |

---

## Project Structure

```
reverse-forensic-tools/
├── config/                   → YAML configuration
├── docs/                     → documentation & assets
├── src/
│   ├── core/                 → CLI (Click), config manager, logger
│   ├── forensic/             → DFIR modules (planned)
│   │   ├── disk_forensic/
│   │   ├── log_analysis/
│   │   ├── memory_forensic/
│   │   └── network_forensic/
│   ├── reverse_engineering/
│   │   └── binary_analysis/  → PE analyzer, ELF analyzer
│   ├── utils/                → hash calculator, file identifier, hex dump
│   └── tests/                → unit & integration tests
├── pyproject.toml
├── requirements.txt
├── Makefile
└── README.md
```

---

## Module Status

| Module | Status | Completion |
|---|---|---|
| Core CLI | ✅ | ~95% |
| Config Manager | ✅ | ~100% |
| Logger | ✅ | ~100% |
| Hash Calculator | ✅ | ~100% |
| File Identifier | ✅ | ~100% |
| Hex Dump Viewer | ✅ | ~100% |
| PE Analyzer | ✅ | ~100% |
| ELF Parser | 🚧 | ~30% |
| Disassembler | ⏳ | ~10% |
| Malware Analysis | ⏳ | ~10% |
| Memory Forensics | ⏳ | ~0% |
| Disk Forensics | ⏳ | ~0% |
| Network Forensics | ⏳ | ~0% |
| Log Analysis | ⏳ | ~0% |

---

## Roadmap

### Phase 1 — Core Utilities + PE Analyzer *(current)*
- ✅ Hash computation (MD5, SHA1, SHA256, SHA512)
- ✅ File type identification via libmagic
- ✅ Hex dump viewer with Rich output
- ✅ PE analyzer: sections, imports, exports, entropy, anomaly detection

### Phase 2 — Binary Analysis + Malware Analysis
- 🚧 ELF analyzer (sections, symbols, security mitigations)
- ⏳ Static malware analysis with YARA integration
- ⏳ IOC extraction (IPs, domains, URLs, hashes)
- ⏳ Disassembler integration (Capstone)

### Phase 3 — DFIR Modules + Reporting
- ⏳ Memory forensics (Volatility3 wrapper)
- ⏳ Disk forensics
- ⏳ Network forensics (PCAP analysis)
- ⏳ Log analysis
- ⏳ Unified report generation

---

## Contributing

1. Fork the repository
2. Create your branch: `git checkout -b feature/module-name`
3. Commit your changes: `git commit -m "feat: add module-name"`
4. Push and open a Pull Request

`CONTRIBUTING.md` coming soon. Issues and feature requests are welcome.

---

## Disclaimer

This toolkit is intended for **authorized use only**. It is designed for educational purposes, security research, and analysis of systems you own or have explicit permission to test. The author is not responsible for any misuse or damage caused by this tool.

---

## License & Author

**MIT License** — see [LICENSE](LICENSE) for details.

**Author:** Operator Cedra  
**GitHub:** [reactivheat](https://github.com/reactivheat)

> *"Nous frappons dans l'ombre pour protéger la lumière."*