\# WinForensicPy



WinForensicPy is a Python-based Windows forensic artifact collection tool designed to collect, organize, and preserve selected Windows forensic artifacts in a structured format.



\## Features



\- Windows system information collection

\- Running process collection

\- Network information collection

\- USB device information collection

\- Windows Registry artifact collection

\- Security event log collection

\- PowerShell event collection

\- Sysmon event collection

\- Chrome history collection

\- Evidence metadata generation

\- SHA-256 integrity hashing

\- JSON-based evidence output

\- Command-line interface

\- Graphical user interface



\## Architecture



WinForensicPy follows a modular collector-based architecture.



```text

WinForensicPy

│

├── Collectors

│   ├── System Information

│   ├── Processes

│   ├── Network

│   ├── USB

│   ├── Registry

│   ├── Security Events

│   ├── PowerShell Events

│   ├── Sysmon Events

│   └── Chrome History

│

├── Evidence Output

│   ├── JSON Writer

│   ├── Metadata Writer

│   ├── Evidence Manager

│   └── Evidence Viewer

│

└── Integrity Utilities

&#x20;   ├── Hash Utilities

&#x20;   └── Hash Writer

