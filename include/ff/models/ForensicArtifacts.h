#pragma once
#include <string>
#include <vector>

#include "ff/utils/json.hpp"

namespace ff::models
{
    // Enum for extending supported browsers
    enum class BrowserType
    {
        MozillaFirefox,
        GoogleChrome,
        MicrosoftEdge,
        Brave
    };

    // Structure for browser bookmarks
    struct BrowserBookmarkEntry
    {
        std::string name;
        std::string url;
    };

    // Update BrowserHistoryEntry structure to support enum
    struct BrowserHistoryEntry
    {
        BrowserType browser; // Which browser was scanned
        std::string url;
        std::string title;
        uint32_t visitCount = 0;
        std::string lastVisitTime;
    };

    struct OsInfo
    {
        std::string osName;
        std::string installDate;
        std::string bootTime;
    };
    
    struct UsbHistoryEntry
    {
        std::string deviceInstanceId; // Serial Number or unique ID
        std::string friendlyName;     // Name USB (example: "SanDisk Cruzer Blade USB Device")
    };

    struct GeoLocation
    {
        double latitude = 0.0;
        double longitude = 0.0;
        std::string source; // "Windows Location API" or "IP-API"
    };

    struct AnonymityStatus
    {
        bool isVpnActive = false;
        bool isProxyActive = false;
        std::string activeAdapters; // VPN adapters or proxy details (e.g., "NordVPN detected", "System Proxy Enabled")
    };

    struct UserActivityEntry
    {
        std::string programPath;
        uint32_t runCount = 0;
        uint32_t totalActiveMinutes = 0;
    };

    struct BluetoothDeviceEntry
    {
        std::string macAddress;
        std::string name;
    };

    // Full collection
    struct DigitalFootprint
    {
        std::vector<UsbHistoryEntry> usbHistory;
        std::vector<UserActivityEntry> userActivity;
        std::vector<BrowserHistoryEntry> browserHistory;
        std::vector<BluetoothDeviceEntry> bluetoothHistory;
        OsInfo osInformation;                           
        GeoLocation location;
        AnonymityStatus anonymity;
    };

    // Serialization for JSON export
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(UsbHistoryEntry, deviceInstanceId, friendlyName)
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(GeoLocation, latitude, longitude, source)
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(AnonymityStatus, isVpnActive, isProxyActive, activeAdapters)
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(DigitalFootprint, usbHistory, location, anonymity)
} // namespace ff::models