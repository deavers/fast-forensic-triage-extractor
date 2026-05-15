#pragma once
#include <vector>
#include <string_view>

#include "ff/Platform.h"
#include "ff/models/ProcessInfo.h"
#include "ff/models/NetworkConn.h"
#include "ff/models/PersistenceEntry.h"

#include "ff/models/ServiceInfo.h"

#include "ff/models/ForensicArtifacts.h"

namespace ff::core
{
    enum class ScanMode
    {
        UnPrivileged, // /proc/net/* - without sudo
        Privileged    // /proc/<pid>/* - with capabilities
    };

    class ISystemScanner
    {
    public:
        virtual ~ISystemScanner() = default;

    protected:
        ISystemScanner() = default;

    public:
        ISystemScanner(const ISystemScanner&) = delete;
        ISystemScanner& operator=(const ISystemScanner&) = delete;

        ISystemScanner(ISystemScanner&&) = default;
        ISystemScanner& operator=(ISystemScanner&&) = default;

        // virtual methods
        virtual std::vector<models::ProcessInfo> scanProcesses() = 0;
        virtual std::vector<models::NetworkConn> scanNetwork() = 0;
        [[nodiscard]] virtual std::string_view platformName() const = 0;

        // Schedule and registry persistence entries (Windows)
        virtual std::vector<models::PersistenceEntry> scanPersistence() = 0;

        // Services and drivers (Windows)
        virtual std::vector<models::ServiceInfo> scanServices() = 0;

        // Forensic artifacts (USB history, geolocation, anonymity status)
        virtual models::DigitalFootprint scanDigitalFootprint() = 0;
    };

} // namespace ff::core