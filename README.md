# WinForensicPy

WinForensicPy is an open-source, modular Python-based framework for collecting selected Windows forensic artifacts and preserving them in a structured format. The software is designed for authorized digital-forensics, incident-response, cybersecurity research, education, and defensive investigations.

## Features

WinForensicPy currently provides collectors for:

- Windows system information
- Running processes
- Network connections
- USB storage devices
- Windows Registry Run Keys
- Windows Security Event Logs
- PowerShell Event Logs
- Sysmon Event Logs
- Chrome browser history

The software also provides:

- Structured JSON evidence output
- Evidence metadata generation
- SHA-256 integrity hashing
- Command-line interface (CLI)
- Graphical user interface (GUI)
- Modular collector architecture
- Extensible output and evidence-management components

## Architecture

WinForensicPy follows a modular collector-based architecture.

```text
WinForensicPy
│
├── Collectors
│   ├── System Information
│   ├── Running Processes
│   ├── Network Connections
│   ├── USB Storage Devices
│   ├── Registry Run Keys
│   ├── Security Event Logs
│   ├── PowerShell Event Logs
│   ├── Sysmon Event Logs
│   └── Chrome History
│
├── Collector Runner
│
├── Evidence Output
│   ├── JSON Writer
│   ├── Metadata Writer
│   ├── Evidence Manager
│   └── Evidence Viewer
│
└── Integrity Utilities
    ├── Hash Utilities
    └── Hash Writer
