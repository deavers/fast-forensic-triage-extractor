#include "LinuxSystemScanner.h"
#include "LinuxRegistry.h"
#include "ff/Platform.h"

#ifdef FF_PLATFORM_LINUX
#include <fstream>

namespace ff::linux_os
{
    LinuxSystemScanner::LinuxSystemScanner(core::ScanMode mode) 
        : m_mode(mode) {}

    std::string_view LinuxSystemScanner::platformName() const
    {
        return ff::kPlatformName; 
    }

    // The main method for collecting the digital footprint of Linux
    models::DigitalFootprint LinuxSystemScanner::scanDigitalFootprint()
    {
        models::DigitalFootprint footprint;
        
        footprint.location.latitude = 49.8308;
        footprint.location.longitude = 18.1625;
        footprint.location.source = "Linux Pseudo-FS Forensic Triage (VSB-TUO Campus)";
        
        footprint.anonymity.isProxyActive = false;

        // Autopilot: We go through all the sub-files-plugins that registered themselves
        for (const auto& subScanner : LinuxRegistry::getScanners())
        {
            subScanner->scan(footprint); // Each sub-scanner fills its own part of the report
        }

        // VPN DETECTION: Check for common VPN interfaces in /proc/net/dev
        footprint.anonymity.isVpnActive = false;
        footprint.anonymity.activeAdapters = "None";

        // Check /proc/net/dev for VPN virtual interfaces
        {
            std::ifstream netDev("/proc/net/dev");
            std::string line;
            static const std::vector<std::pair<std::string, std::string>> vpnIfaces = {
                { "tun",        "TUN VPN (OpenVPN/WireGuard)" },
                { "tap",        "TAP VPN (OpenVPN)"           },
                { "nordlynx",   "NordVPN (WireGuard)"         },
                { "wg",         "WireGuard"                   },
                { "tailscale",  "Tailscale"                   },
                { "mullvad",    "Mullvad VPN"                 },
                { "proton",     "ProtonVPN"                   },
            };

            while (std::getline(netDev, line))
            {
                for (const auto& [ifacePrefix, displayName] : vpnIfaces)
                {
                    // /proc/net/dev lines look like: "  tun0:  12345 ..."
                    std::string trimmed = line;
                    trimmed.erase(0, trimmed.find_first_not_of(" \t"));

                    if (trimmed.rfind(ifacePrefix, 0) == 0)
                    {
                        footprint.anonymity.isVpnActive = true;

                        // Extract interface name (before ':')
                        std::string ifaceName = trimmed.substr(0, trimmed.find(':'));
                        footprint.anonymity.activeAdapters = displayName + " [" + ifaceName + "]";
                        goto vpn_found; // break out of both loops
                    }
                }
            }
            vpn_found:;
        }

        // Check proxy via env variables (http_proxy / HTTPS_PROXY)
        if (!footprint.anonymity.isProxyActive)
        {
            const char* httpProxy  = std::getenv("http_proxy");
            const char* httpsProxy = std::getenv("https_proxy");
            const char* allProxy   = std::getenv("all_proxy");
            
            if ((httpProxy  && httpProxy[0]  != '\0') ||
                (httpsProxy && httpsProxy[0] != '\0') ||
                (allProxy   && allProxy[0]   != '\0'))
            {
                footprint.anonymity.isProxyActive = true;
            }
        }
        
        return footprint;
    }

} // namespace ff::linux_os
#endif // FF_PLATFORM_LINUX