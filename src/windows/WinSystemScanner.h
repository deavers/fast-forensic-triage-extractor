#pragma once
#include "ff/Platform.h"

#ifdef FF_PLATFORM_WINDOWS

#include <vector>
#include <string>
#include <optional>
#include <string_view>

// Network
#include <winsock2.h>
#include <iphlpapi.h>

#include "ff/core/ISystemScanner.h"
#include "ff/models/ProcessInfo.h"
#include "ff/models/NetworkConn.h"
#include "ff/models/PersistenceEntry.h"

#include "ff/models/ServiceInfo.h"

namespace ff::windows
{
    // final because from this class no one will inherit
    class WinSystemScanner final : public core::ISystemScanner
    {
    public:
        explicit WinSystemScanner(core::ScanMode mode = core::ScanMode::UnPrivileged);
        ~WinSystemScanner() = default;

        // Perhibeatly delete copy operations, allow move semantics
        WinSystemScanner(const WinSystemScanner&) = delete;
        WinSystemScanner& operator=(const WinSystemScanner&) = delete;
        WinSystemScanner(WinSystemScanner&&) = default;
        WinSystemScanner& operator=(WinSystemScanner&&) = default;

        // virutal methods from ISystemScanner
        std::vector<models::ProcessInfo> scanProcesses() override;
        std::vector<models::NetworkConn> scanNetwork() override;
        
        [[nodiscard]] std::string_view platformName() const override;

        // Schedule and registry persistence entries (Windows)
        std::vector<models::PersistenceEntry> scanPersistence() override;

        // Services and drivers (Windows)
        std::vector<models::ServiceInfo> scanServices() override;

        // Forensic artifacts (USB history, geolocation, anonymity status)
        models::DigitalFootprint scanDigitalFootprint() override;

    private:
        core::ScanMode m_mode;
        
        // Functions to get process information, used internally by scanProcesses
        std::optional<std::string> getProcessPath(uint32_t pid) const;
        bool isProcessElevated(uint32_t pid) const;
    };

} // namespace ff::windows

#endif // FF_PLATFORM_WINDOWS