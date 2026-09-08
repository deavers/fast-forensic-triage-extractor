# Fast Forensic Triage Extractor (FFTE)

> A C++20 live-response triage tool for collecting selected forensic artefacts
> from Windows and Linux hosts and exporting them to structured JSON reports.

[![Language](https://img.shields.io/badge/Language-C%2B%2B20-00599C?logo=c%2B%2B&logoColor=white)](#)
[![Platforms](https://img.shields.io/badge/Platforms-Windows%20%7C%20Linux-2ea44f)](#)
[![Build](https://img.shields.io/badge/Build-CMake-064F8C?logo=cmake&logoColor=white)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

FFTE is an educational Digital Forensics and Incident Response (DFIR) project
for the initial review of a potentially compromised or suspicious host.

It gathers selected process, network, persistence, filesystem, and operating
system artefacts using native Windows APIs and Linux `/proc` data sources.
The collected data is exported as structured JSON for later analyst review.

> [!WARNING]
> FFTE is a live-response triage tool. It is **not** a replacement for forensic
> disk imaging, memory acquisition, validated enterprise DFIR tooling, or an
> analyst-led investigation.

---

## Highlights

- Cross-platform C++20 collection for Windows and Linux
- Native collection interfaces: WinAPI, WMI, Registry APIs, Event Log APIs, and `/proc`
- Modular, self-registering collector architecture
- Structured JSON reports
- Local HTML viewer for filtering and reviewing reports
- No Python runtime or external collection framework required

---

## Collected artefacts

The availability of individual artefacts depends on the operating system,
privileges, endpoint-security controls, and host configuration.

<details>
<summary><strong>Windows</strong></summary>

### Processes and memory indicators

- Running processes and process metadata
- Process start times and integrity levels
- SHA-256 hashes of selected executable images
- Process environment information
- Executable writable-memory-region indicators for analyst review
- Clipboard collection where access is available

### Network and system information

- Active TCP and UDP connections
- ARP table and DNS cache
- Network adapters, MAC addresses, and proxy configuration
- Hosts-file contents and Windows Firewall rules
- Operating-system and boot metadata
- SMBIOS hardware information through WMI

### Persistence and registry artefacts

- `HKLM\...\Run` and `HKCU\...\Run` autorun entries
- Startup-folder entries
- Scheduled-task registry entries
- Windows services and BootExecute configuration
- Winlogon-related registry entries
- Browser-extension registry locations
- USBSTOR and Bluetooth device history
- UserAssist artefacts with ROT13 decoding
- RDP-related registry artefacts

### Filesystem and event artefacts

- Windows Prefetch file inventory
- Browser-history database discovery where accessible
- Windows Event Log queries, including failed-logon events
- Pagefile, hibernation-file, and swapfile metadata
- Authenticode trust verification for selected executable or driver files

</details>

<details>
<summary><strong>Linux</strong></summary>

### Processes and kernel information

- Process metadata from `/proc`
- Open file descriptors from `/proc/[pid]/fd`
- Process environment variables from `/proc/[pid]/environ`
- UID and GID information from `/proc/[pid]/status`
- cgroup paths for containerisation context
- Loaded kernel-module inventory from `/proc/modules`

### System and filesystem information

- Mounted filesystems from `/proc/mounts`
- Installed-package inventory for DPKG- and RPM-based systems
- Systemd units and scheduled-task locations
- SSH `authorized_keys` locations
- Network-interface information
- Virtual-adapter indicators, including TUN/TAP-style interfaces

</details>

---

## Architecture

FFTE uses a modular, self-registering collector architecture. Each collector is
implemented as an independent module and registers with the collection engine
during program startup.

```text
FFTE Core
│
├── Collector Registry
│   ├── Windows Collectors
│   │   ├── Processes and memory
│   │   ├── Registry and persistence
│   │   ├── Network
│   │   └── Filesystem and event logs
│   │
│   └── Linux Collectors
│       ├── Processes and kernel
│       ├── Filesystem and packages
│       └── Network and services
│
└── JSON Report Writer
    └── Local HTML Report Viewer
```

### Design choices

| Component | Approach |
|---|---|
| Language | C++20 with RAII-based resource management |
| Windows sources | WinAPI, WMI, Registry API, Event Log API |
| Linux sources | `/proc` pseudo-filesystem and standard system locations |
| Report format | Structured JSON |
| Analysis | Local browser-based HTML viewer |
| Build system | CMake |

---

## Requirements

### Windows

- Windows 10 or Windows 11
- CMake 3.20+
- Microsoft Visual Studio / MSVC Build Tools, or MinGW-w64 with C++20 support

### Linux

- Modern Linux distribution
- CMake 3.20+
- GCC or Clang with C++20 support
- `sudo` access recommended for broader artefact collection

---

## Build

Clone the repository:

```bash
git clone [https://github.com/deavers/fast-forensic-triage-extractor.git](https://github.com/deavers/fast-forensic-triage-extractor.git)
cd fast-forensic-triage-extractor
```

### Windows — MSVC

```powershell
cmake -S . -B build
cmake --build build --config Release
```

### Windows — MinGW-w64

```bash
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build --config Release
```

### Linux

```bash
cmake -S . -B build_linux
cmake --build build_linux
```

---

## Usage

### Windows

Run the built executable:

```powershell
.\fastforensics.exe
```

Specify an output path:

```powershell
.\fastforensics.exe --output C:\forensics\forensics_report_windows.json
```

For broader access to protected artefacts, launch it from an elevated terminal:

```powershell
Start-Process -FilePath ".\fastforensics.exe" -Verb RunAs
```

### Linux

Run the compiled binary:

```bash
./fastforensics
```

Specify an output path:

```bash
./fastforensics --output /tmp/forensics_report_linux.json
```

Run with elevated privileges when required:

```bash
sudo ./fastforensics
```

---

## Output and viewer

FFTE creates a platform-specific JSON report:

```text
forensics_report_windows.json
forensics_report_linux.json
```

Example structure:

```json
{
  "report_metadata": {
    "tool": "FFTE",
    "platform": "Windows",
    "collection_time_utc": "2026-01-01T12:00:00Z"
  },
  "processes": [],
  "network": {
    "tcp_connections": [],
    "udp_connections": [],
    "dns_cache": []
  },
  "persistence": {
    "run_keys": [],
    "services": [],
    "scheduled_tasks": []
  }
}
```

To use the local viewer:

1. Build and run FFTE to generate a JSON report.
2. Open `viewer.html` in a modern browser.
3. Select the generated JSON report.
4. Search, filter, review, and export supported report sections.

The viewer processes the selected report locally in the browser; it does not
require an external server.

---

## Privacy and handling

Generated reports can contain sensitive material, including usernames, file
paths, network addresses, device names, hardware identifiers, browser artefacts,
process arguments, environment variables, and clipboard contents.

Treat every report as sensitive investigation material:

- Store it securely.
- Do not publish real reports.
- Redact personal and organisational data before sharing examples.
- Use test systems or explicitly authorised systems only.

---

## Limitations

FFTE provides an initial live-response snapshot. Results may be incomplete
because of insufficient privileges, protected processes, locked files, endpoint
security controls, OS-version differences, virtualisation, containerisation,
or attacker tampering.

Collected artefacts require validation and correlation with trusted logs,
forensic images, and investigation context. FFTE does not make a definitive
compromise determination.

---

## Roadmap

- [ ] Sanitised sample reports for Windows and Linux
- [ ] Automated tests for selected collectors
- [ ] Additional artefact collectors
- [ ] Improved error reporting and cross-platform report normalisation
- [ ] Performance improvements for filesystem-heavy collection
- [ ] More filters and export options in the HTML viewer

---

## References

- Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006). *Guide to Integrating
  Forensic Techniques into Incident Response (NIST SP 800-86).*  
  https://csrc.nist.gov/pubs/sp/800/86/final

- Microsoft Learn — Windows API documentation  
  https://learn.microsoft.com/windows/win32/api/

- Microsoft Learn — Windows Event Log API  
  https://learn.microsoft.com/windows/win32/wes/windows-event-log

- Microsoft Learn — Windows Registry  
  https://learn.microsoft.com/windows/win32/sysinfo/registry

- Microsoft Learn — `WinVerifyTrust`  
  https://learn.microsoft.com/windows/win32/api/wintrust/nf-wintrust-winverifytrust

- Linux manual pages — `proc(5)`  
  https://man7.org/linux/man-pages/man5/procfs.5.html

- MITRE ATT&CK  
  https://attack.mitre.org/

---

## Legal notice

Use FFTE only on systems, files, and networks that you own or where you have
explicit authorisation to collect and analyse data.

The author is not responsible for misuse, unauthorised collection, privacy
violations, or damage resulting from use of this software.

---

## License

This project is licensed under the [MIT License](LICENSE).
