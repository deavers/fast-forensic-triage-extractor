#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace ff::models
{
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

    struct BluetoothDeviceEntry
    {
        std::string name;
        std::string macAddress;
    };

    // Linux Specific Function 30
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

    // Windows Specific Function 32
    struct ArpTableEntry
    {
        std::string ipAddress;
        std::string macAddress;
        std::string type;
    };

    // Windows Specific Function 33
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

    // Global structure to hold all forensic artifacts and information
    struct DigitalFootprint
    {
        OsInfo osInformation;
        GeoLocation location;
        AnonymityStatus anonymity;

        // Vectors to hold platform-specific artifacts
        std::vector<UsbHistoryEntry> usbHistory;
        std::vector<UserActivityEntry> userActivity;
        std::vector<BrowserHistoryEntry> browserHistory;
        std::vector<BluetoothDeviceEntry> bluetoothHistory;


        // Vectors to hold cross-platform artifacts
        std::vector<std::string> installedSoftware; // Active software and low-level processes
        std::vector<std::string> hostsLines;        // Cross-platform network socket bindings
    
        // Cross-platform dynamic artifacts
        std::vector<KernelModule> linuxModules;
        std::vector<SshKeyEntry> sshKeys;
        std::vector<ArpTableEntry> arpEntries;
        std::vector<FirewallRuleEntry> firewallRules;
    };
}