#!/usr/bin/env python3
"""Setup script for Reverse Engineering & Digital Forensic Tools package."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="reverse-forensic-tools",
    version="1.0.0",
    author="Operator Cedra",
    author_email="",
    description="A comprehensive Python toolkit for Reverse Engineering and Digital Forensic analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="",
    project_urls={"Bug Tracker": "", "Documentation": "", "Source Code": ""},
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.10",
    install_requires=[
        "capstone>=4.0.0", "keystone-engine>=0.9.2", "pefile>=2023.2.7",
        "pyelftools>=0.29", "unicorn>=2.0.0", "volatility3>=2.0.0",
        "scapy>=2.5.0", "pyts>=0.12.0", "dfir-ntfs>=2022.1.0",
        "artifacts>=2023.1.0", "yara-python>=4.3.0", "pandas>=2.0.0",
        "numpy>=1.24.0", "matplotlib>=3.7.0", "pyyaml>=6.0.0",
        "requests>=2.31.0", "psutil>=5.9.0", "python-magic>=0.4.27",
        "protobuf>=4.21.0", "rich>=13.0.0",
    ],
    entry_points={"console_scripts": ["rf-tools=core.cli:main"]},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords=[
        "reverse-engineering", "digital-forensics", "malware-analysis",
        "binary-analysis", "disassembly", "decompilation", "forensics", "security"
    ],
    license="MIT",
    include_package_data=True,
)