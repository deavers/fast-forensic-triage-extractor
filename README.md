# 🛡️ Fast Forensic Triage Extractor (FFTE)

> A high-performance, cross-platform (Windows WinAPI / Linux Pseudo-FS) forensic live response triage collection tool. Implemented in pure C++20 with an automated, self-registering plugin architecture and built-in anti-reverse engineering protections.

## 🚀 Architecture Overview
* **Zero-Dependency Core:** Only relies on native OS APIs (`<windows.h>`, `<iphlpapi.h>`, `/proc`).
* **Autopilot Plugin System:** Modules self-register into the RAM at runtime before `main()` executes via static initialization vectors.
* **Stealth & Evasion:** Includes XOR string obfuscation and Anti-Debugging Honeypot mechanics to feed fake Decoy data to debuggers (IDA Pro / x64dbg).
* **Const-Correctness & RAII:** Strictly follows modern C++20 resource management principles to prevent memory leaks during forensic data extraction.

---

## 🎓 Academic Integrity & Contribution Matrix

*Note for Reviewers: This table demonstrates full transparency regarding the development process of the 50 core forensic capabilities.* * **Idea:** Who architected the forensic logic and selected the artifact vector.
* **Realization:** Who wrote the actual C++ implementation (Me = Student, AI = LLM Assistant, AI+Me = Pair Programming/Refactoring).

| ID | Function / Forensic Artifact | Platform | Idea | Realization |
|:---|:---|:---:|:---:|:---|
| **01** | Cross-Platform Factory Architecture | Core | Me | AI + Me |
| **02** | Automated Plugin Registry System | Core | Me | AI |
| **03** | JSON Exporter & Serialization | Core | Me | AI + Me |
| **04** | Decoupled Console Printer Triage | Core | Me | AI + Me |
| **05** | Anti-Debug Honeypot (Decoy System) | Core | Me | AI + Me |
| **06** | OS Name & Install Date Extraction | Win / Lin | Me | AI + Me |
| **07** | Precise System Boot Time (Uptime) | Win / Lin | Me | Me |
| **08** | Process Snapshot (Toolhelp32) | Windows | Me | Me |
| **09** | Process Executable Path Resolution | Windows | Me | AI + Me |
| **10** | Authenticode Signature Check (WinTrust) | Windows | Me | AI |
| **11** | Elevated Privileges Detection (Token) | Windows | Me | Me |
| **12** | TCP IPv4 Active Connections (tcpmib) | Windows | Me | AI + Me |
| **13** | TCP IPv6 Active Connections | Windows | Me | AI + Me |
| **14** | Persistence: HKCU Registry Run Keys | Windows | Me | Me |
| **15** | Persistence: HKLM Registry Run Keys | Windows | Me | Me |
| **16** | Service Control Manager (SCM) Dump | Windows | Me | AI + Me |
| **17** | Native Kernel Driver Detection (.sys) | Windows | Me | Me |
| **18** | USB History Extraction (USBSTOR) | Windows | Me | AI + Me |
| **19** | USB Device Serial Number Parsing | Windows | Me | AI + Me |
| **20** | Active VPN / Proxy Status Detection | Windows | Me | Me |
| **21** | Geolocation Triage (Campus GPS) | Cross | Me | Me |
| **22** | UserAssist Execution History | Windows | Me | AI + Me |
| **23** | UserAssist ROT13 Decoder | Windows | Me | Me |
| **24** | UserAssist Focus Time Calculator | Windows | Me | AI + Me |
| **25** | Mozilla Firefox `places.sqlite` Triage | Windows | Me | Me |
| **26** | SQLite Modification Timestamp Parsing | Windows | Me | AI + Me |
| **27** | Bluetooth Paired Devices (BTHPORT) | Windows | Me | Me |
| **28** | Environment Variables Memory Dump | Windows | Me | Me |
| **29** | Pseudo-FS Process Iteration (`/proc`) | Linux | Me | AI + Me |
| **30** | **Resident Kernel Modules (LKM)** | Linux | Me | AI + Me |
| **31** | Network Interfaces Status Triage | Linux | Me | Me |
| **32** | **Kernel ARP Table Extraction** | Windows | Me | AI + Me |
| **33** | **Active Firewall Rules Triage** | Windows | Me | AI + Me |
| **34** | **SSH Authorized Keys Extraction** | Linux | Me | AI + Me |
| **35** | Process Environment (`/proc/pid/environ`) | Linux | Me | Pending |
| **36** | Open File Descriptors (`/proc/pid/fd`) | Linux | Me | Pending |
| **37** | Process Credentials (UID/GID parsing) | Linux | Me | Pending |
| **38** | TCP Connections (`/proc/net/tcp`) | Linux | Me | Me |
| **39** | TCPv6 Connections (`/proc/net/tcp6`) | Linux | Me | Me |
| **40** | Linux Scheduled Tasks (Cron) | Linux | Me | Pending |
| **41** | Linux Bash History Scan | Linux | Me | Pending |
| **42** | Process Command Line (`cmdline`) | Linux | Me | Pending |
| **43** | Sudoers Configuration Check | Linux | Me | Pending |
| **44** | Shadow Hash Presence Validation | Linux | Me | Pending |
| **45** | Memory Mappings (`/proc/pid/maps`) | Linux | Me | Pending |
| **46** | Windows Prefetch Parsing | Windows | Me | Pending |
| **47** | Windows Event Logs (Sec 4624) | Windows | Me | Pending |
| **48** | Active RDP Sessions Triage | Windows | Me | Pending |
| **49** | Amcache Triage Execution Logs | Windows | Me | Pending |
| **50** | Unified JSON Report Marshalling | Core | Me | AI + Me |

---

## 🛠️ Build Instructions
This project uses CMake and requires a compiler with C++20 support (MSVC `/std:c++20` or GCC `-std=c++20`).

**Windows (MinGW/GCC or MSVC):**
```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release

**Linux (WSL / Debian):**
```bash
mkdir build_linux && cd build_linux
cmake ..
cmake --build .