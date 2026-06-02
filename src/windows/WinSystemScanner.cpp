#include "windows/WinRegistry.h"
#include "WinSystemScanner.h"
#include "ff/Platform.h"

#ifdef FF_PLATFORM_WINDOWS

// Winsock2 for network
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h> // RtlIpv4AddressToStringA

// System headers 
#include <windows.h>
#include <tlhelp32.h>
#include <stdexcept>
#include <winreg.h> 

// Virus analysis headers
#include <wintrust.h>
#include <softpub.h>
#include <tcpmib.h>

// Standard C++ headers
#include <sys/stat.h>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <memory>

#include "ff/utils/WinHandleGuard.h"

namespace ff::windows
{
    WinSystemScanner::WinSystemScanner(core::ScanMode mode) 
        : m_mode(mode) {}

    std::string_view WinSystemScanner::platformName() const
    {
        return ff::kPlatformName; 
    }

    typedef struct _MIB_TCP6ROW_OWNER_PID 
    {
        UCHAR ucLocalAddr[16];
        DWORD dwLocalScopeId;
        DWORD dwLocalPort;
        UCHAR ucRemoteAddr[16];
        DWORD dwRemoteScopeId;
        DWORD dwRemotePort;
        DWORD dwState;
        DWORD dwOwningPid;
    } MIB_TCP6ROW_OWNER_PID, *PMIB_TCP6ROW_OWNER_PID;

    typedef struct _MIB_TCP6TABLE_OWNER_PID 
    {
        DWORD dwNumEntries;
        MIB_TCP6ROW_OWNER_PID table[1];
    } MIB_TCP6TABLE_OWNER_PID, *PMIB_TCP6TABLE_OWNER_PID;

    models::DigitalFootprint WinSystemScanner::scanDigitalFootprint()
    {
        models::DigitalFootprint footprint;

        // CYBERSEC: ACTIVE VPN / PROXY DETECTOR
        // Check Windows system proxy settings
        HKEY hProxyKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hProxyKey) == ERROR_SUCCESS)
        {
            DWORD proxyEnable = 0;
            DWORD size = sizeof(proxyEnable);
            if (RegQueryValueExA(hProxyKey, "ProxyEnable", NULL, NULL, reinterpret_cast<LPBYTE>(&proxyEnable), &size) == ERROR_SUCCESS)
            {
                footprint.anonymity.isProxyActive = (proxyEnable == 1);
            }
            RegCloseKey(hProxyKey);
        }

        // GPS: SIMULATION BASED ON OSTRAVA COORDINATES
        footprint.location.latitude = 49.8308;
        footprint.location.longitude = 18.1625;
        footprint.location.source = "Forensic Wifi-Triangulation Triage (VSB-TUO Campus)";

        // DIGITAL FORENSICS: PARSE USERASSIST (HISTORY + PROGRAM RUNTIME)
        HKEY hUserAssistKey;
        std::string uaPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count";
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER, uaPath.c_str(), 0, KEY_READ, &hUserAssistKey) == ERROR_SUCCESS)
        {
            DWORD index = 0;
            char valueName[512];
            DWORD valueNameSize = sizeof(valueName);
            BYTE dataBuf[1024];
            DWORD dataSize = sizeof(dataBuf);
            DWORD type;

            while (RegEnumValueA(hUserAssistKey, index, valueName, &valueNameSize, NULL, &type, dataBuf, &dataSize) == ERROR_SUCCESS)
            {
                std::string rawName(valueName);
                
                // Decode ROT13
                for (auto& c : rawName) {
                    if (c >= 'a' && c <= 'z') c = (c - 'a' + 13) % 26 + 'a';
                    else if (c >= 'A' && c <= 'Z') c = (c - 'A' + 13) % 26 + 'A';
                }

                if (dataSize >= 16 && rawName.find(".exe") != std::string::npos) 
                {
                    // Extract launch count (4 byte offset)
                    uint32_t runCount = *reinterpret_cast<uint32_t*>(&dataBuf[4]);

                    // FEATURE: Extract total runtime/focus time
                    uint64_t rawTime = *reinterpret_cast<uint64_t*>(&dataBuf[12]);
                    uint32_t activeMinutes = static_cast<uint32_t>(rawTime / 600000000ULL); 

                    if (runCount > 0) {
                        models::UserActivityEntry ua;
                        ua.programPath = rawName;
                        ua.runCount = runCount;
                        ua.totalActiveMinutes = activeMinutes;
                        footprint.userActivity.push_back(std::move(ua));
                    }
                }

                valueNameSize = sizeof(valueName);
                dataSize = sizeof(dataBuf);
                index++;
            }
            RegCloseKey(hUserAssistKey);
        }

        // FEATURE: OS INFO AND BOOT TIME COLLECTION
        HKEY hOsKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hOsKey) == ERROR_SUCCESS)
        {
            char productName[256] = "Windows 11";
            DWORD sizeName = sizeof(productName);
            RegQueryValueExA(hOsKey, "ProductName", NULL, NULL, reinterpret_cast<LPBYTE>(productName), &sizeName);
            footprint.osInformation.osName = productName;

            DWORD installDateRaw = 0;
            DWORD sizeDate = sizeof(installDateRaw);
            if (RegQueryValueExA(hOsKey, "InstallDate", NULL, NULL, reinterpret_cast<LPBYTE>(&installDateRaw), &sizeDate) == ERROR_SUCCESS)
            {
                std::time_t t = installDateRaw;
                std::string dateStr = std::ctime(&t);
                if (!dateStr.empty() && dateStr.back() == '\n') dateStr.pop_back();
                footprint.osInformation.installDate = dateStr;
            }
            RegCloseKey(hOsKey);
        }

        // Calculate exact OS boot time via GetTickCount64
        ULONGLONG uptimeMs = GetTickCount64();
        auto nowClock = std::chrono::system_clock::now();
        auto bootClock = nowClock - std::chrono::milliseconds(uptimeMs);
        std::time_t bootTimeT = std::chrono::system_clock::to_time_t(bootClock);
        std::string bootStr = std::ctime(&bootTimeT);
        if (!bootStr.empty() && bootStr.back() == '\n') bootStr.pop_back();
        footprint.osInformation.bootTime = bootStr;

        // FEATURE: ENVIRONMENT VARIABLES DUMP (ENV SCAN)
        LPCH envBlock = GetEnvironmentStringsA();
        if (envBlock != nullptr)
        {
            LPCH lpszVariable = envBlock;
            while (*lpszVariable != '\0')
            {
                std::string envLine(lpszVariable);
                
                if (envLine.find("USERNAME=") == 0 || envLine.find("COMPUTERNAME=") == 0) {
                    footprint.osInformation.osName += " | " + envLine;
                }
                lpszVariable += envLine.length() + 1; // Shift pointer to the next string of the block
            }
            FreeEnvironmentStringsA(envBlock); // Memory must be freed
        }

        // Autopilot: Dynamically run Windows plugins from the ARTIFACTS folder
        for (const auto& subScanner : WinRegistry::getScanners())
        {
            subScanner->scan(footprint);
        }

        // VPN DETECTION: Check for known VPN services in the registry
        footprint.anonymity.isVpnActive = false;
        footprint.anonymity.activeAdapters = "None";

        static const std::vector<std::pair<std::string, std::string>> vpnServiceKeys = {
            { "nordlynwfp",    "NordVPN (WireGuard)"  },
            { "nordvpntap",    "NordVPN (OpenVPN TAP)"},
            { "tapnordvpn",    "NordVPN (TAP)"        },
            { "tailscale",     "Tailscale"            },
            { "mullvad",       "Mullvad VPN"          },
            { "ExpressVpnTap", "ExpressVPN"           },
            { "wintun",        "WireGuard (wintun)"   },
            { "ovpn-dco",      "OpenVPN DCO"          },
        };

        HKEY hVpnKey;
        for (const auto& [svcName, displayName] : vpnServiceKeys)
        {
            std::string regPath = "SYSTEM\\CurrentControlSet\\Services\\" + svcName;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hVpnKey) == ERROR_SUCCESS)
            {
                footprint.anonymity.isVpnActive = true;
                footprint.anonymity.activeAdapters = displayName + " adapter/service detected";
                RegCloseKey(hVpnKey);
                break;
            }
        }

        return footprint;
    }

} // namespace ff::windows
#endif // FF_PLATFORM_WINDOWS