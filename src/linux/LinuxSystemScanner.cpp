#include "LinuxSystemScanner.h"
#include "LinuxRegistry.h"
#include "ff/Platform.h"

#ifdef FF_PLATFORM_LINUX

namespace ff::linux_os
{
    LinuxSystemScanner::LinuxSystemScanner(core::ScanMode mode) 
        : m_mode(mode) {}

    std::string_view LinuxSystemScanner::platformName() const
    {
        return ff::kPlatformName; 
    }

    std::vector<models::ProcessInfo> LinuxSystemScanner::scanProcesses() { return {}; }
    std::vector<models::NetworkConn> LinuxSystemScanner::scanNetwork() { return {}; }
    std::vector<models::PersistenceEntry> LinuxSystemScanner::scanPersistence() { return {}; }
    std::vector<models::ServiceInfo> LinuxSystemScanner::scanServices() { return {}; }

    // The main method for collecting the digital footprint of Linux
    models::DigitalFootprint LinuxSystemScanner::scanDigitalFootprint()
    {
        models::DigitalFootprint footprint;
        
        footprint.location.latitude = 49.8308;
        footprint.location.longitude = 18.1625;
        footprint.location.source = "Linux Pseudo-FS Forensic Triage (VSB-TUO Campus)";
        
        footprint.anonymity.isProxyActive = false;
        footprint.anonymity.isVpnActive = false;
        footprint.anonymity.activeAdapters = "None";

        // Autopilot: We go through all the sub-files-plugins that registered themselves
        for (const auto& subScanner : LinuxRegistry::getScanners())
        {
            subScanner->scan(footprint); // Each sub-scanner fills its own part of the report
        }
        
        return footprint;
    }

} // namespace ff::linux_os
#endif // FF_PLATFORM_LINUX