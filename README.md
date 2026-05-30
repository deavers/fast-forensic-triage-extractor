# 🛡️ Fast Forensic Triage Extractor (FFTE)

> A high-performance, cross-platform (Windows WinAPI / Linux Pseudo-FS) forensic live response triage collection tool. Implemented in pure C++20 with an automated, self-registering plugin architecture and built-in anti-reverse engineering protections.

## 🚀 Architecture Overview

* **Zero-Dependency Core:** Only relies on native OS APIs (`<windows.h>`, `<iphlpapi.h>`, `/proc`).
* **Autopilot Plugin System:** Modules self-register into the RAM at runtime before `main()` executes via static initialization vectors.
* **Stealth & Evasion:** Includes XOR string obfuscation and Anti-Debugging Honeypot mechanics to feed fake Decoy data to debuggers (IDA Pro / x64dbg).
* **Const-Correctness & RAII:** Strictly follows modern C++20 resource management principles to prevent memory leaks during forensic data extraction.

---

## 🎓 Academic Integrity & 50 Forensic Artifacts Matrix

*Note for Reviewers: These tables demonstrate full transparency regarding the development process of the 50 core forensic capabilities.* 
* **Idea:** Who architected the forensic logic and selected the artifact vector.
* **Realization:** Who wrote the actual C++ implementation (Me = Student, AI = LLM Assistant, AI+Me = Pair Programming/Refactoring, Pending = Planned).

### 🖥️ Windows — Processes & Memory (`WinSystemScanner.cpp`)

| # | Function / Capability | Description | Idea | Realization |
|:---|:---|:---|:---:|:---:|
| **1** | `scanHiddenProcesses()` | Hidden processes search via `NtQuerySystemInformation` | Me | AI + Me |
| **2** | `extractProcessMemory()` | `MiniDumpWriteDump` implementation for critical processes | Me | Pending |
| **3** | `getProcessHash()` | SHA256 hashing of running executable files | Me | AI + Me |
| **4** | `scanProcessThreads()` | Thread entry enumeration for each process | Me | Pending |
| **5** | `getProcessEnvironment()` | Process environment variables extraction | Me | Me |
| **6** | `scanInjectedDLLs()` | DLL injection detection via `ReadProcessMemory` | Me | Pending |
| **7** | `getProcessStartTime()` | Exact process launch timestamp calculation | Me | AI + Me |
| **8** | `scanProcessHandles()` | Open process handles enumeration | Me | Pending |
| **9** | `extractProcessCommandLine()`| Command-line arguments extraction | Me | AI + Me |
| **10** | `getProcessIntegrityLevel()` | Integrity level check (Low/Medium/High/System) | Me | Me |

### 🖥️ Windows — Registry & Autorun (`WinSystemScanner.cpp`)

| # | Function / Capability | Description | Idea | Realization |
|:---|:---|:---|:---:|:---:|
| **11** | `scanHKLM_Run()` | `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` | Me | Me |
| **12** | `scanHKCU_Run()` | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | Me | Me |
| **13** | `scanStartupFolder()` | Startup folder parsing for current and all users | Me | AI + Me |
| **14** | `scanScheduledTasks()` | TaskScheduler COM interface enumeration | Me | Pending |
| **15** | `scanBootExecute()` | `HKLM\System\CurrentControlSet\Control\Session Manager` | Me | Me |
| **16** | `scanWinlogonNotify()` | DLLs in `Winlogon\Notify` registry key | Me | AI + Me |
| **17** | `scanBrowserExtensions()` | Browser extensions analysis in the registry | Me | Pending |
| **18** | `scanShellExtensions()` | `ShellExecuteHooks` analysis in the registry | Me | Pending |
| **19** | `scanAppInitDLLs()` | `AppInit_DLLs` persistence check | Me | Me |
| **20** | `scanImageFileExecution()` | IFEO hierarchy check for process hollowing/replacement | Me | AI + Me |

### 🖥️ Windows — System & Drivers (`WinSystemScanner.cpp`)

| # | Function / Capability | Description | Idea | Realization |
|:---|:---|:---|:---:|:---:|
| **21** | `scanKernelDrivers()` | `EnumServicesStatusExW` with `SERVICE_KERNEL_DRIVER` | Me | AI + Me |
| **22** | `verifyDriverSignature()` | Authenticode validation via `WinVerifyTrust` | Me | AI |
| **23** | `scanFailedDriverLoads()` | EventLog: System, source `ServiceControlManager` | Me | Pending |
| **24** | `scanBootDrivers()` | Boot-start and System-start drivers enumeration | Me | Pending |
| **25** | `getWindowsInstallDate()` | `InstallDate` in `HKLM\Software\Microsoft\Windows NT` | Me | Me |
| **26** | `getWindowsLastShutdown()` | Last shutdown timestamp from EventLog: System | Me | Pending |
| **27** | `scanPagefileUsage()` | Size and exact location of `pagefile.sys` | Me | Pending |
| **28** | `scanHibernationFile()` | Hibernate file analysis (`hiberfil.sys`) | Me | Pending |
| **29** | `scanSwapFileUsage()` | `swapfile.sys` extraction for Windows 10/11 | Me | Pending |
| **30** | `scanTempFiles()` | Triage of `C:\Windows\Temp` and `%TEMP%` directories | Me | Me |

### 🌐 Windows — Network & Connections (`WinSystemScanner.cpp`)

| # | Function / Capability | Description | Idea | Realization |
|:---|:---|:---|:---:|:---:|
| **31** | `getTCPConnections()` | `GetExtendedTcpTable` mapping for IPv4 and IPv6 | Me | AI + Me |
| **32** | `getUDPConnections()` | `GetExtendedUdpTable` extraction | Me | Me |
| **33** | `scanDNSCache()` | `DnsFlushResolverCache` and DNS Cache analysis | Me | Pending |
| **34** | `scanARPTable()` | `GetIpNetTable` implementation for MAC addresses | Me | AI + Me |
| **35** | `getNetworkAdapters()` | `GetAdaptersInfo` for all network interfaces | Me | Me |
| **36** | `scanFirewallRules()` | `netsh advshow firewall rule` logic extraction | Me | AI + Me |
| **37** | `getProxySettings()` | WinINET and `CurrentVersion\Internet Settings` | Me | Me |
| **38** | `scanHostsFile()` | Parse and analyze `C:\Windows\System32\drivers\etc\hosts` | Me | AI + Me |
| **39** | `getWinsockProviders()` | Winsock LSP check for hidden proxy layers | Me | Pending |
| **40** | `scanRecentConnections()` | Recent WiFi networks (`HKLM\Software\Microsoft\WlanSvc`) | Me | Me |

### 🐧 Linux — Processes & Memory (`artifacts/`)

| # | Function / Capability | Description | Idea | Realization |
|:---|:---|:---|:---:|:---:|
| **41** | `scanKernelModules()` | Parse `/proc/modules` for resident loaded modules (LKM) | Me | AI + Me |
| **42** | `getProcessOpenFiles()` | Read `/proc/[pid]/fd` for active file descriptors | Me | Pending |
| **43** | `getProcessEnvironment()` | Read `/proc/[pid]/environ` for active variables | Me | Pending |
| **44** | `getProcessCredentials()` | Parse UID/GID security context from `/proc/[pid]/status` | Me | Pending |
| **45** | `scanCgroups()` | `cgroups` isolation checks for containers (Docker/LXC) | Me | Pending |

### 🐧 Linux — Filesystem & Packages (`artifacts/`)

| # | Function / Capability | Description | Idea | Realization |
|:---|:---|:---|:---:|:---:|
| **46** | `scanInstalledPackages()` | `dpkg -l` (Debian/Ubuntu) or `rpm -qa` (Fedora/RHEL) | Me | Pending |
| **47** | `scanScheduledTasks()` | Triage of `/etc/crontab` and `/var/spool/cron/` | Me | Pending |
| **48** | `scanSystemdUnits()` | Execution of `systemctl list-units --type=service` | Me | Pending |
| **49** | `scanMountPoints()` | Dump `/proc/mounts` for all mounted filesystems | Me | Me |
| **50** | `scanSSHKeys()` | Parse `~/.ssh/authorized_keys` for remote access traces | Me | AI + Me |

---

## 🛠️ Build Instructions

This project uses CMake and requires a compiler with C++20 support (MSVC `/std:c++20` or GCC `-std=c++20`).

**Windows (MinGW/GCC or MSVC):**

```bash
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

---

**Linux (WSL / Debian):**

```bash
mkdir build_linux && cd build_linux
cmake ..
cmake --build .
```