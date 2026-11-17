# Fast Forensic Triage Extractor (FFTE)

> A C++20 live-response triage and behavioral sandbox telemetry engine for collecting forensic artefacts from Windows and Linux hosts, performing pre/post execution state diffing, and exporting structured JSON reports for machine learning and local AI incident analysis (`MITRE ATT&CK`).

![Language](https://img.shields.io/badge/Language-C%2B%2B20-00599C?style=flat-square&logo=c%2B%2B)
![Platforms](https://img.shields.io/badge/Platforms-Linux%20%7C%20Windows-FCC624?style=flat-square&logo=linux)
![Build](https://img.shields.io/badge/Build-CMake%203.20%2B-064F8C?style=flat-square&logo=cmake)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

**FFTE** is a Digital Forensics, Incident Response (DFIR), and Malware Sandbox Instrumentation project designed for the rapid assessment of potentially compromised hosts and isolated virtual machines.

It gathers process, memory, network, persistence, filesystem, and static binary artefacts (including ELF/PE headers and Shannon entropy) using native Windows APIs and Linux `/proc` & `<elf.h>` interfaces. The collected telemetry is exported as structured JSON for automated anomaly scoring and interactive analyst review via a local browser-based dashboard and offline Small Language Model (SLM) assistant.

> [!WARNING]
> FFTE is a live-response triage and sandbox telemetry tool. It is **not** a replacement for full forensic disk imaging, raw physical memory acquisition, validated enterprise EDR/DFIR tooling, or an analyst-led investigation.

> **Status (Nov 2026):** implemented — Linux collectors for processes, modules, packages,
> systemd units, cron, SSH keys. Planned — `--baseline`/`--diff`, entropy/ELF triage,
> ML scoring, local AI report.

---

## Highlights

- **Cross-platform C++20 engine** for Linux and Windows with strict RAII-based resource management
- **Native collection interfaces:** Linux `/proc`, `/sys`, `<elf.h>`, `inotify`/`auditd`, and Windows `WinAPI`, `WMI`, `Registry API`, `Event Log API`
- **Pre/Post Execution State Diffing (`--baseline` / `--diff`):** isolates behavioral changes induced by a sample inside a Linux KVM sandbox while filtering out benign OS background noise
- **Static Binary & Payload Entropy Triage:** computes global and sliding-window Shannon entropy ($0.00 - 8.00\text{ bits/byte}$) and inspects ELF segments (`RWX` permissions, stripped symbols, embedded commands)
- **Three-Layer Triage Pipeline:** deterministic C++20 rules $\rightarrow$ classical ML anomaly scoring (`DBSCAN` / `LightGBM`) $\rightarrow$ offline local AI incident reporting (`Llama-3.2` / `Qwen-2.5` via `llama.cpp` / `Ollama`) mapped to **MITRE ATT&CK**
- **No Python runtime or heavy external agent dependencies** required inside the guest OS for core collection

---

## Collected Artefacts

The availability of individual artefacts depends on the operating system, privileges, endpoint-security controls, and host configuration.

<details>
<summary><strong>Linux (Live-Response & Malware Sandbox Telemetry)</strong></summary>

### Processes, credentials, and memory indicators
- Process hierarchy and metadata from `/proc/[pid]/stat` and `/proc/[pid]/cmdline`
- Open file descriptors and socket symlinks from `/proc/[pid]/fd`
- Process environment variables from `/proc/[pid]/environ`
- UID, GID, capabilities, and `TracerPid` indicators from `/proc/[pid]/status`
- `cgroup` paths for containerisation context
- Fileless execution and memory anomalies (`/memfd:`, `(deleted)` binaries in `/proc/[pid]/exe`, and anonymous `rwxp` segments in `/proc/[pid]/maps`)

### Network, persistence, kernel, and static analysis
- Active socket tables from `/proc/net/{tcp,udp,raw,arp}` with hex IP:Port decoding and socket `inode`-to-PID mapping
- `/etc/hosts` and `/etc/resolv.conf` tampering inspection
- Loaded kernel-module inventory from `/proc/modules`
- Mounted filesystems (`/proc/mounts`), installed packages (`DPKG` / `RPM`), `systemd` units, `cron` jobs, and SSH `authorized_keys`
- Static binary `<elf.h>` header/section analysis (`Elf64_Ehdr`, `Elf64_Phdr`, `Elf64_Shdr`) and Shannon entropy profiling ($0.00 - 8.00\text{ bits/byte}$)
- Staging directory (`/tmp`, `/dev/shm`) differential entropy spike detection and host resource saturation (`/proc/stat`, `/proc/meminfo`)

</details>

<details>
<summary><strong>Windows (Live-Response Collectors)</strong></summary>

### Processes and memory indicators
- Running processes, start times, integrity levels, and process metadata
- SHA-256 hashes and Authenticode trust verification (`WinVerifyTrust`) of executable images
- Process environment information and executable writable-memory-region (`RWX`) indicators
- Clipboard collection where access is available

### Network and system information
- Active TCP and UDP connections (`GetExtendedTcpTable` / `GetExtendedUdpTable`)
- ARP table, DNS cache, network adapters, MAC addresses, proxy configuration, Hosts file, and Windows Firewall rules
- Operating-system, boot metadata, and SMBIOS hardware information through WMI

### Persistence, registry, and filesystem artefacts
- `HKLM\...\Run`, `HKCU\...\Run`, Startup folders, Scheduled Tasks, Services, `BootExecute`, and `Winlogon` registry entries
- Browser extensions, browser-history discovery, `USBSTOR`, Bluetooth device history, `UserAssist` (ROT13), and RDP artefacts
- Windows Prefetch inventory, Event Log queries (including failed logons), and pagefile/hibernation/swapfile metadata

</details>

---

## Architecture

FFTE uses a modular, self-registering collector architecture. Each scanner is implemented as an independent C++20 module and registers with the collection engine during startup.

```text
FFTE Core Engine (C++20)
│
├── Collector Registry
│   ├── Linux Collectors (/proc, <elf.h>, filesystem)
│   │   ├── Processes, Credentials, FDs, Env, cgroups & Memory Hunt (memfd / deleted exe / RWX)
│   │   ├── Persistence & Kernel (Cron, Systemd, SSH Keys, Packages, LKM /proc/modules)
│   │   ├── Network (/proc/net/{tcp,udp,raw,arp}, Socket Inode-to-PID Mapper, /etc/hosts)
│   │   ├── Static Sample & Entropy Analyzer (<elf.h> headers, Shannon Entropy 0-8 bit/B)
│   │   └── Runtime & Filesystem Delta (/tmp, /dev/shm Ransomware entropy spike & Host Load)
│   │
│   └── Windows Collectors (WinAPI, WMI, Registry, Event Logs)
│       ├── Processes, Services, Prefetch, Clipboard, User Activity, WMI & MemHunt
│       ├── Registry Persistence, Scheduled Tasks, USB, Bluetooth, RDP & Browser Extensions
│       └── Network Connections, ARP, DNS Cache, Firewall & Hosts File
│
└── JSON Telemetry & Diff Exporter
    ├── Stage 1: Deterministic Rule Hints & ZSU Feature Vector (Entropy, Throughput, Host Load)
    ├── Stage 2: Interactive Local HTML Report Viewer (viewer.html)
    └── Stage 3: Offline Local AI Assistant (llama.cpp / Ollama -> MITRE ATT&CK Report)
```

---

## Design Choices

| Component | Approach |
| :--- | :--- |
| **Language** | C++20 with strict RAII-based resource management |
| **Linux Sources** | `/proc` pseudo-filesystem, `<elf.h>`, standard persistence & staging paths |
| **Windows Sources** | WinAPI, WMI, Registry API, Event Log API |
| **Sandbox Mode** | Differential snapshot comparison ($\Delta S = S_{\text{post}} \setminus S_{\text{pre}}$) |
| **Report Format** | Strictly typed JSON schema (`nlohmann/json`) |
| **Visualization & AI** | Local browser-based HTML dashboard (`viewer.html`) with optional offline `llama.cpp` / `Ollama` chat |
| **Build System** | CMake 3.20+ |

---

## Build Instructions

Clone the repository:

```bash
git clone https://github.com/deavers/fast-forensic-triage-extractor.git
cd fast-forensic-triage-extractor
```

### Linux (GCC or Clang with C++20 support)

```bash
cmake -S . -B build_linux -DCMAKE_BUILD_TYPE=Release
cmake --build build_linux -j$(nproc)
```

### Windows — MSVC

```powershell
cmake -S . -B build
cmake --build build --config Release
```

### Windows — MinGW-w64

```powershell
cmake -S . -B build -G "MinGW Makefiles"
cmake --build build --config Release
```

---

## Usage

### 1. Standard Live-Response Snapshot (Linux & Windows)

```bash
# Linux (run with sudo for full /proc/[pid]/fd and /proc/[pid]/maps access)
sudo ./build_linux/fastforensics --output /tmp/forensics_report_linux.json
```

```powershell
# Windows (run from an elevated Administrator terminal)
.\build\Release\fastforensics.exe --output C:\forensics\forensics_report_windows.json
```

### 2. Linux Malware Sandbox Differential Mode (Pre/Post Execution)

```bash
# Step 1: Capture clean baseline snapshot inside the KVM guest before execution
sudo ./build_linux/fastforensics --mode baseline --output /tmp/pre.json

# Step 2: Execute controlled scenario or suspicious ELF/script sample (isolated network)
./sandbox_sample.elf

# Step 3: Capture post-execution state, analyze sample entropy, and export delta report
sudo ./build_linux/fastforensics --mode diff \
  --baseline /tmp/pre.json \
  --sample ./sandbox_sample.elf \
  --output /tmp/sandbox_diff_report.json
```

---

## 🗺️ RPG Development Roadmap & Literature Progression

This repository serves as the core forensic and behavioral telemetry engine for the Bachelor's Thesis **"Linux Sandbox for Malware Analysis with Local AI"** at FEI VŠB-TUO.

| Tier | Rank | Core Literature & Chapters | Target Engineering Milestone in FFTE | Status |
| :--- | :--- | :--- | :--- | :---: |
| **Lv. 1–20** | 🟢 **Initiate** | *NIST SP 800-86* & *MS Learn Win32/WMI Docs* | Core C++20 `ISystemScanner` / `IArtifactSubScanner` registry, 19 Windows collectors, 9 base Linux collectors, JSON exporter & `viewer.html` | ✅ Done |
| **Lv. 21–35** | 🔵 **Scout** | *Practical Linux Forensics* (Nikkel, 2021 — Ch. 4, 5, 8) & `man 5 proc` | Implement `ProcNetScanner.cpp` (`/proc/net/{tcp,udp,raw,arp}` + socket inode-to-PID mapping) & `HostLoadScanner.cpp` (`/proc/stat` CPU & `/proc/meminfo` RAM) | ⏳ Active |
| **Lv. 36–50** | 🔵 **Hunter (BSc)** | *Evasive Malware* (Cucci, 2024 — Ch. 2, 16–18) & *Practical Binary Analysis* (Andriesse — Ch. 2) | Implement `PayloadEntropyScanner.cpp` (`<elf.h>` + Shannon entropy `0.0–8.0`), `LinuxMemHuntScanner.cpp` (`memfd:` / `(deleted)` / `rwxp`), `Pre/Post Diff` engine & Local AI Viewer | ⏳ Active |
| **Lv. 51–80** | 🟣 **Master (MSc)** | *BPF Performance Tools* (Gregg) & *The Art of Memory Forensics* (Ch. 19–25) | Kernel-space `eBPF` (`libbpf`) real-time syscall sensor (`sys_enter_execve`, `memfd_create`, `ptrace`, `connect`) to capture short-lived processes | 🔒 Planned |
| **Lv. 81–99** | 🔴 **Sovereign** | *Evasive Malware* (Cucci, 2024 — Ch. 4–15) & *LibVMI / DRAKVUF Docs* | Anti-evasion hardened KVM orchestrator (SMBIOS/CPUID spoofing, TSC normalization) & automated runtime memory unpacker | 🔒 Planned |

### Directory Expansion Plan (`src/linux/artifacts/`)

```text
src/linux/artifacts/
├── filesystem/
│   ├── CronScanner.cpp              [Implemented]
│   ├── PkgScanner.cpp               [Implemented]
│   ├── SshKeyScanner.cpp            [Implemented]
│   ├── SystemdScanner.cpp           [Implemented]
│   └── TempEntropyDiffScanner.cpp   [Planned - Lv. 35: /tmp & /dev/shm Ransomware/Dropper diff]
├── kernel/
│   └── LkmScanner.cpp               [Implemented]
├── process/
│   ├── CgroupScanner.cpp            [Implemented]
│   ├── ProcCredScanner.cpp          [Implemented]
│   ├── ProcEnvScanner.cpp           [Implemented]
│   ├── ProcFdScanner.cpp            [Implemented]
│   └── LinuxMemHuntScanner.cpp      [Planned - Lv. 40: /proc/[pid]/maps RWX & memfd/deleted exe]
├── network/
│   ├── ProcNetScanner.cpp           [Planned - Lv. 25: /proc/net/{tcp,udp,raw,arp} + socket inode mapper]
│   └── LinuxHostsScanner.cpp        [Planned - Lv. 25: /etc/hosts & /etc/resolv.conf tampering]
├── static/
│   └── PayloadEntropyScanner.cpp    [Planned - Lv. 30: Native <elf.h> parser & Shannon Entropy 0.0-8.0]
└── system/
    └── HostLoadScanner.cpp          [Planned - Lv. 25: /proc/stat CPU & /proc/meminfo RAM telemetry]
```

### Detailed Skill Tree: Literature, Labs & Milestones

#### 🟢 Tier 1 (Lv. 1–25): Linux Live-Response Adept
- **📖 Required Reading:**
  - *Practical Linux Forensics* (Bruce Nikkel, 2021):
    - **Ch. 4:** Directory Layout and Forensic Analysis of Linux Files (`/proc`, `/sys`, `/tmp`, `/dev/shm`, MACb timestamps, SUID/SGID).
    - **Ch. 5 & 6:** Linux System Logs & Initialization/Persistence (`systemd`, `cron`, `authorized_keys`, `/etc/ld.so.preload`).
    - **Ch. 8:** Identifying Network Configuration Artifacts (`/proc/net/tcp`, hex little-endian IP:Port decoding, socket inodes).
  - *Linux Manual Pages:* `man 5 proc` (`/proc/[pid]/stat`, `/proc/[pid]/fd`, `/proc/net/tcp`).
- **⚔️ Hands-On Training:** Parse hex-encoded IPv4 addresses and ports from `/proc/net/tcp` manually and map socket `inode` numbers to running PIDs via `/proc/[pid]/fd/*` symlinks.
- **🛠️ Project Deliverable:** Implement `ProcNetScanner.cpp` and `HostLoadScanner.cpp` (`/proc/stat` CPU usage & `/proc/meminfo` RAM saturation).

#### 🔵 Tier 2 (Lv. 26–50): Sandbox & Malware Hunter (BSc Thesis Target)
- **📖 Required Reading:**
  - *Evasive Malware: A Field Guide to Detecting, Analyzing, and Defeating Advanced Threats* (Kyle Cucci, No Starch Press, 2024):
    - **Ch. 2:** Malware Triage and Behavioral Analysis (Static inspection, hashing, section entropy).
    - **Ch. 16 & 17:** Encoding, Encryption & Packers (Byte probability distribution & high-entropy detection).
    - **Ch. 18 & Appendix A:** Building an Anti-Evasion Analysis Lab (QEMU/KVM isolation, Host-Only networking, FakeNet/INetSim).
  - *Practical Binary Analysis* (Dennis Andriesse, 2018):
    - **Ch. 2:** The ELF Format (`Elf64_Ehdr`, `Elf64_Phdr`, `Elf64_Shdr`, `PT_LOAD` permissions).
  - *Academic Paper:* Lyda, R., & Hamrock, J. (2007). *Using Entropy Analysis to Find Encrypted and Packed Malware.* IEEE Security & Privacy.
- **⚔️ Hands-On Training:** Benchmark FFTE against 12 controlled synthetic scenarios (6 Bash & 6 Python scripts: Plaintext ASCII $H \approx 4.5$ vs. Raw Ciphertext $H \approx 7.99$) and real Linux ELF samples from *MalwareBazaar* (`Mirai`, `Gafgyt`, `Kinsing`) inside an isolated KVM guest.
- **🛠️ Project Deliverables:**
  - Implement `PayloadEntropyScanner.cpp` ($0.0 - 8.0$ Shannon entropy + `<elf.h>` header anomalies).
  - Implement Pre/Post State Diffing (`--baseline pre.json --diff post.json`) to filter out benign OS background noise and prevent false positives.
  - Upgrade `viewer.html` with a split-screen Local AI Assistant (`Ollama` / `llama.cpp`) for automated **MITRE ATT&CK** incident reporting.

#### 🟣 Tier 3 (Lv. 51–80): Kernel & Memory Forensics Master (MSc Target)
- **📖 Required Reading:**
  - *BPF Performance Tools* (Brendan Gregg) & *Learning eBPF* (Liz Rice) — **Ch. 1, 2, 8, 10** (`kprobes`, `tracepoints`, `libbpf`).
  - *The Art of Memory Forensics* (Michael Hale Ligh et al.) — **Ch. 19–25** (Linux kernel structures, `task_struct`, rootkit detection in RAM).
- **⚔️ Hands-On Training:** Capture live memory dumps using `LiME` / `virsh dump-memory` and analyze fileless `memfd_create()` payloads in **Volatility 3**.
- **🛠️ Project Deliverable:** Build an `eBPF` kernel telemetry collector for FFTE that hooks `sys_enter_execve`, `sys_enter_memfd_create`, `sys_enter_ptrace`, and `sys_enter_connect` in real time to catch short-lived processes (`<10ms`).

#### 🔴 Tier 4 (Lv. 81–99): Sovereign Sandbox Architect (God-Tier)
- **📖 Required Reading:**
  - *Evasive Malware* (Kyle Cucci, 2024) — **Ch. 4–15** (Anti-VM, CPUID/SMBIOS spoofing, `rdtsc` timing attacks, anti-debugging).
  - *Xen VMI / LibVMI & DRAKVUF Documentation*.
- **🛠️ Project Deliverable:** Anti-evasion KVM hardening suite (custom QEMU DMI/ACPI tables, MAC/hardware ID randomization) + automated memory dumper for packed ELF binaries.

---

## Privacy, OPSEC, and Legal Notice

- Generated reports contain sensitive host material, including usernames, file paths, network addresses, process arguments, environment variables, and hardware identifiers.
- Store reports securely and redact personal/organisational data before sharing examples.
- Never execute untrusted binaries on a production host; always use an isolated virtual machine without shared folders or NAT access to production networks.
- Use FFTE only on systems, files, and networks that you own or where you have explicit authorisation to collect and analyse data.

---

## References

- Cucci, K. (2024). *Evasive Malware: A Field Guide to Detecting, Analyzing, and Defeating Advanced Threats.* No Starch Press.
- Nikkel, B. (2021). *Practical Linux Forensics: A Guide for Digital Investigators.* No Starch Press.
- Andriesse, D. (2018). *Practical Binary Analysis: Build Your Own Linux Tools for Binary Instrumentation, Analysis, and Disassembly.* No Starch Press.
- Saxe, J., & Sanders, H. (2018). *Malware Data Science: Attack Detection and Attribution.* No Starch Press.
- Lyda, R., & Hamrock, J. (2007). *Using Entropy Analysis to Find Encrypted and Packed Malware.* IEEE Security & Privacy, 5(2), 40–45.
- Kent, K., Chevalier, S., Grance, T., & Dang, H. (2006). *Guide to Integrating Forensic Techniques into Incident Response (NIST SP 800-86).*
- MITRE ATT&CK® Enterprise Matrix — https://attack.mitre.org/

---

## License

This project is licensed under the [MIT License](LICENSE).
