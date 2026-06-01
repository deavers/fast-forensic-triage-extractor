#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <string_view>

#include "PersistenceEntry.h"
#include "ProcessInfo.h"
#include "ServiceInfo.h"

namespace ff::models
{
    struct HardwareInfo
    {
        std::string cpuName;
        std::string gpuName;
        std::string totalRamGB;
        std::string motherboardSerial; // SMBIOS
    };

    enum class BrowserType
    {
        MozillaFirefox,
        Chrome,
        Edge,
        Other
    };

    // Helper: convert BrowserType enum to string for JSON serialization
    constexpr std::string_view toString(BrowserType t) noexcept
    {
        switch (t)
        {
            case BrowserType::MozillaFirefox: return "Firefox";
            case BrowserType::Chrome:         return "Chrome";
            case BrowserType::Edge:           return "Edge";
            default:                          return "Other";
        }
    }

    struct UsbHistoryEntry
    {
        std::string deviceInstanceId;
        std::string friendlyName;
    };

    struct UserActivityEntry
    {
        std::string programPath;
        uint32_t runCount = 0;
        uint32_t totalActiveMinutes = 0;
    };

    struct BrowserHistoryEntry
    {
        BrowserType browser = BrowserType::Other;
        std::string url;
        std::string title;
        uint32_t visitCount = 0;
        std::string lastVisitTime;
    };

    struct PrefetchEntry
    {
        std::string executableName;
        std::string prefetchFileName;
        std::string lastRunTime;
    };

    struct BluetoothDeviceEntry
    {
        std::string name;
        std::string macAddress;
    };

    // Linux Kernel Modules (Function 30)
    struct KernelModule
    {
        std::string name;
        std::string size;
        std::string state;
    };

    // Linux Remote Access Artifacts (Function 34)
    struct SshKeyEntry
    {
        std::string path;
        std::string keyContent;
    };

    // Windows Network Artifacts (Function 32)
    struct ArpTableEntry
    {
        std::string ipAddress;
        std::string macAddress;
        std::string type;
    };

    struct NetworkConnEntry
    {
        std::string protocol;
        std::string localIp;
        std::string localPort;
        std::string remoteIp;
        std::string remotePort;
        std::string state;
    };

    // Windows Firewall Rules (Function 33)
    struct FirewallRuleEntry
    {
        std::string ruleName;
        std::string ruleData;
    };

    // Infrastructure and Environment Artifacts
    struct OsInfo
    {
        std::string osName = "Unknown OS";
        std::string installDate = "Unknown";
        std::string bootTime = "Unknown";
    };
    struct GeoLocation
    {
        double latitude = 0.0;
        double longitude = 0.0;
        std::string source = "None";
    };
    struct AnonymityStatus
    {
        bool isProxyActive = false;
        bool isVpnActive = false;
        std::string activeAdapters = "None";
    };

    // LINUX
    // Process environment and file descriptor artifacts
    struct ProcEnvEntry
    {
        std::string pid;
        std::string envDump;
    };
    struct ProcFdEntry
    {
        std::string pid;
        std::string openFiles;
    };

    // Process credentials and cgroup artifacts
    struct ProcCredEntry
    {
        std::string pid;
        std::string uid_info;
        std::string gid_info;
    };
    struct ProcCgroupEntry
    {
        std::string pid;
        std::string containerPath;
        bool isContainerized = false;
    };

    // Linux-specific infrastructure artifacts
    struct PkgInfo
    {
        std::string name;
        std::string version;
    };
    struct CronTask
    {
        std::string taskLine;
        std::string filePath;
    };
    struct SystemdUnit
    {
        std::string name;
        std::string state;
    };

    struct RdpSession
    {
        std::string targetHost;
        std::string usernameHint;
    };

    struct EventLogEntry
    {
        std::string eventId;
        std::string timestamp;
        std::string details;
    };

    struct InjectedMemoryEntry
    {
        std::string pid;
        std::string processName;
        std::string memoryAddress;
        std::string protection;
    };

    struct ClipboardEntry
    {
        std::string format;
        std::string content;
        std::string sizeBytes;
    };

    struct BrowserExtensionEntry
    {
        std::string browser;
        std::string extensionId;
        std::string updateUrl;
    };

    struct DnsCacheEntry
    {
        std::string recordName;
        std::string recordType;
        std::string data;
    };

    struct SystemFileEntry
    {
        std::string fileName;
        std::string sizeMB;
        std::string notes;
    };

    // Global structure to hold all forensic artifacts and information
    struct DigitalFootprint
    {
        // HARDWARE, OS & LOCATION
        HardwareInfo hw_info;
        OsInfo osInformation;
        GeoLocation location;
        AnonymityStatus anonymity;

        // WEB & BROWSER ARTIFACTS
        std::vector<BrowserHistoryEntry> browserHistory;
        std::vector<BrowserExtensionEntry> browserExtensions;
        std::vector<DnsCacheEntry> dnsCache;

        // NETWORK & CONNECTIVITY
        std::vector<NetworkConnEntry> networkConnections;
        std::vector<ArpTableEntry> arpEntries;
        std::vector<FirewallRuleEntry> firewallRules;
        std::vector<BluetoothDeviceEntry> bluetoothHistory;
        std::vector<std::string> hostsLines;

        // PROCESSES, MEMORY & SYSTEM FILES
        std::vector<ProcessInfo> processes;
        std::vector<InjectedMemoryEntry> injectedMemory;
        std::vector<SystemFileEntry> systemFiles;

        // PERSISTENCE & EXECUTION
        std::vector<PersistenceEntry> persistence;
        std::vector<PrefetchEntry> prefetchFiles;
        std::vector<CronTask> scheduledTasks;
        std::vector<ServiceInfo> services;
        std::vector<UserActivityEntry> userActivity;

        // SECURITY LOGS & EXFILTRATION
        std::vector<EventLogEntry> eventLogs;
        std::vector<RdpSession> rdpSessions;
        std::vector<ClipboardEntry> clipboardData;
        std::vector<UsbHistoryEntry> usbHistory;

        // LINUX SPECIFIC
        std::vector<std::string> installedSoftware;
        std::vector<KernelModule> linuxModules;
        std::vector<SshKeyEntry> sshKeys;
        std::vector<ProcEnvEntry> processEnvironments;
        std::vector<ProcFdEntry> processFileDescriptors;
        std::vector<ProcCredEntry> processCredentials;
        std::vector<ProcCgroupEntry> processCgroups;
        std::vector<PkgInfo> installedPackages;
        std::vector<SystemdUnit> systemdUnits;
    };
}
