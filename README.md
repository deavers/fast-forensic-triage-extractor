## 🎓 Academic Integrity & Contribution Matrix

*Note for Reviewers: This table demonstrates full transparency regarding the development process.* * **Idea:** Who architected the forensic logic.
* **Realization:** Who wrote the actual C++ implementation.

### 🔥 Top 10 Advanced DFIR Capabilities (High Complexity)
*These modules interact directly with OS kernels, undocumented structures, or advanced evasion techniques.*

| # | Forensic Module | Data Extracted / Method | Idea | Status / Coder |
|:---:|:---|:---|:---:|:---:|
| **1** | **Authenticode Verification** | Calls `WinVerifyTrust` to detect unsigned Rootkit `.sys` drivers. | AI | ✅ AI |
| **2** | **LKM Triage (Linux)** | Parses `/proc/modules` to detect hidden Linux Kernel Modules. | AI | ✅ AI + Me |
| **3** | **IFEO / AppInit Persistence** | Extracts stealthy registry hooking mechanisms used by APTs. | AI | ❌ Pending |
| **4** | **Injected DLL Detection** | Reads process memory to find unbacked executable memory regions. | AI | ❌ Pending |
| **5** | **Process Memory MiniDump** | Executes `MiniDumpWriteDump` for offline Yara scanning. | Me | ❌ Pending |
| **6** | **Kernel ARP Table** | Queries `GetIpNetTable` to bypass user-land network spoofing. | Me | ✅ AI + Me |
| **7** | **Hidden Processes Scan** | Uses `NtQuerySystemInformation` to bypass Task Manager hooks. | AI | ❌ Pending |
| **8** | **Container Isolation (cgroups)** | Detects if the malware/system is running inside Docker/LXC. | AI | ❌ Pending |
| **9** | **Winsock LSP Hijacks** | Inspects hidden proxy layers intercepting network traffic. | AI | ❌ Pending |
| **10** | **Focus Time Calculator** | Translates 64-bit Windows FILETIME into active user screen-time. | Me | ✅ AI + Me |

---

### 🖥️ Windows — Processes & Memory (`WinSystemScanner.cpp`)

| # | Capability | Data Extracted / Method | Idea | Status / Coder |
|:---:|:---|:---|:---:|:---:|
| **11** | `getProcessHash()` | SHA256 hashing of active memory executables | AI | ❌ Pending |
| **12** | `scanProcessThreads()` | Thread entry base addresses | Me | ❌ Pending |
| **13** | `getProcessEnvironment()` | Process memory environment blocks | Me | ✅ Me |
| **14** | `getProcessStartTime()` | Absolute UTC launch timestamps | Me | ✅ AI + Me |
| **15** | `scanProcessHandles()` | Locked files, mutexes, and registry keys | Me | ❌ Pending |
| **16** | `getProcessIntegrity()` | Security tokens (Low/Medium/High/System) | Me | ✅ Me |

### 🖥️ Windows — Registry & Autorun (`WinSystemScanner.cpp`)

| # | Capability | Data Extracted / Method | Idea | Status / Coder |
|:---:|:---|:---|:---:|:---:|
| **17** | `scanHKLM_Run()` | Global auto-start executables | Me | ✅ Me |
| **18** | `scanHKCU_Run()` | User-specific auto-start executables | Me | ✅ Me |
| **19** | `scanStartupFolder()` | LNK files in Startup directories | Me | ✅ AI + Me |
| **20** | `scanScheduledTasks()` | COM interface TaskScheduler XML dumps | Me | ❌ Pending |
| **21** | `scanBootExecute()` | Session Manager boot-time execution | Me | ✅ Me |
| **22** | `scanWinlogonNotify()` | Logon notification stealth DLLs | AI | ✅ AI + Me |
| **23** | `scanBrowserExtensions()`| Malicious registry browser hooks | Me | ❌ Pending |

### 🖥️ Windows — System & Drivers (`WinSystemScanner.cpp`)

| # | Capability | Data Extracted / Method | Idea | Status / Coder |
|:---:|:---|:---|:---:|:---:|
| **24** | `scanFailedDriverLoads()` | EventLog traces of failed rootkit injection | AI | ❌ Pending |
| **25** | `getWindowsInstallDate()` | Epoch timestamp of OS installation | Me | ✅ Me |
| **26** | `getWindowsLastShutdown()`| Dirty/Clean shutdown logs | Me | ❌ Pending |
| **27** | `scanPagefileUsage()` | Size and path of `pagefile.sys` RAM dump | AI | ❌ Pending |
| **28** | `scanHibernationFile()` | Size and path of `hiberfil.sys` | AI | ❌ Pending |
| **29** | `scanSwapFileUsage()` | Size and path of `swapfile.sys` | AI | ❌ Pending |
| **30** | `scanTempFiles()` | Triage of `%TEMP%` executable payloads | Me | ✅ Me |

### 🌐 Windows — Network (`WinSystemScanner.cpp`)

| # | Capability | Data Extracted / Method | Idea | Status / Coder |
|:---:|:---|:---|:---:|:---:|
| **31** | `getTCPConnections()` | IPv4/IPv6 Active bound sockets | Me | ✅ AI + Me |
| **32** | `getUDPConnections()` | UDP listening ports | Me | ✅ Me |
| **33** | `scanDNSCache()` | Local DNS resolution history | Me | ❌ Pending |
| **34** | `getNetworkAdapters()` | Hardware MACs and active DHCP | Me | ✅ Me |
| **35** | `scanFirewallRules()` | Dump of active allowed/blocked ports | AI | ✅ AI + Me |
| **36** | `getProxySettings()` | WinINET default gateway overrides | Me | ✅ Me |
| **37** | `scanHostsFile()` | Contents of `etc/hosts` DNS hijacking | Me | ✅ AI + Me |

### 🐧 Linux — Processes & Filesystem (`artifacts/`)

| # | Capability | Data Extracted / Method | Idea | Status / Coder |
|:---:|:---|:---|:---:|:---:|
| **41** | `scanKernelModules()` | `/proc/modules` load base and sizes | AI | ✅ AI + Me |
| **42** | `getProcessOpenFiles()` | Symlinks from `/proc/[pid]/fd` | AI | ✅ AI + Me |
| **43** | `getProcessEnvironment()` | Null-byte separated `/proc/[pid]/environ` | AI | ✅ AI + Me |
| **44** | `getProcessCredentials()` | Real/Effective UID & GID from `status` | AI | ✅ AI + Me |
| **45** | `scanCgroups()` | Isolation paths (Docker/Kubernetes/LXC) | AI | ✅ AI + Me |
| **46** | `scanInstalledPackages()` | DPKG/RPM software inventory lists | Me | ❌ Pending |
| **47** | `scanScheduledTasks()` | Contents of `/etc/crontab` | Me | ❌ Pending |
| **48** | `scanSystemdUnits()` | Enabled `systemctl` services | AI | ❌ Pending |
| **49** | `scanMountPoints()` | `/proc/mounts` remote/local drives | Me | ✅ Me |
| **50** | `scanSSHKeys()` | `~/.ssh/authorized_keys` persistence | Me | ✅ AI + Me |

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