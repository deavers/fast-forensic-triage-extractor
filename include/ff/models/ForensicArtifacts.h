#pragma once
#include <string>
#include <vector>
#include <cstdint>

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



    // Global structure to hold all forensic artifacts and information
    struct DigitalFootprint
    {
        HardwareInfo hw_info;
        OsInfo osInformation;
        GeoLocation location;
        AnonymityStatus anonymity;

        // Vectors to hold platform-specific artifacts
        std::vector<UsbHistoryEntry> usbHistory;
        std::vector<UserActivityEntry> userActivity;
        std::vector<BrowserHistoryEntry> browserHistory;
        std::vector<BluetoothDeviceEntry> bluetoothHistory;

        // Windows-specific artifacts
        std::vector<PrefetchEntry> prefetchFiles;

        // Vectors to hold cross-platform artifacts
        std::vector<std::string> installedSoftware; // Active software and low-level processes
        std::vector<std::string> hostsLines;        // Cross-platform network socket bindings
    
        // Cross-platform dynamic artifacts
        std::vector<KernelModule> linuxModules;
        std::vector<SshKeyEntry> sshKeys;
        std::vector<ArpTableEntry> arpEntries;
        std::vector<FirewallRuleEntry> firewallRules;

        // Process environment and file descriptor artifacts
        std::vector<ProcEnvEntry> processEnvironments;
        std::vector<ProcFdEntry> processFileDescriptors;

        // Process credentials and cgroup artifacts
        std::vector<ProcCredEntry> processCredentials;
        std::vector<ProcCgroupEntry> processCgroups;

        // Linux-specific infrastructure artifacts
        std::vector<PkgInfo> installedPackages;
        std::vector<CronTask> scheduledTasks;
        std::vector<SystemdUnit> systemdUnits;

        // Remote access and event log artifacts
        std::vector<RdpSession> rdpSessions;
        std::vector<EventLogEntry> eventLogs;

        std::vector<NetworkConnEntry> networkConnections;
        std::vector<ArpTableEntry> arpTable;

        // Memory injection artifacts
        std::vector<InjectedMemoryEntry> injectedMemory;
    };
}