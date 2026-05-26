#include <iostream>
#include <memory>
#include <vector>
#include <string>

#include "ff/Platform.h"
#include "ff/core/ISystemScanner.h"
#include "ff/models/ProcessInfo.h"
#include "ff/models/PersistenceEntry.h"
#include "ff/models/NetworkConn.h"

#include "ff/core/Exporter.h"

// Multiplatform includes
#ifdef FF_PLATFORM_WINDOWS
    #include "windows/WinSystemScanner.h"
#elif defined(FF_PLATFORM_LINUX)
    #include "linux/LinuxSystemScanner.h"
#endif

namespace ff
{
    std::unique_ptr<core::ISystemScanner> createScanner()
    {
        #if defined(FF_PLATFORM_WINDOWS)
            return std::make_unique<windows::WinSystemScanner>(core::ScanMode::UnPrivileged);
        #elif defined(FF_PLATFORM_LINUX)
            return std::make_unique<linux_os::LinuxSystemScanner>(core::ScanMode::UnPrivileged);
        #else
            return nullptr;
        #endif
    }

    void printProcesses(const std::vector<models::ProcessInfo>& procs)
    {
        std::cout << "Starting process enumeration...\n";
        std::cout << "--------------------------------------------------\n";
        for (const auto& proc : procs)
        {
            std::cout << "[PID: " << proc.pid << "]\t" << proc.name;
            
            // Display signature verification status
            if (proc.isSignatureValid) {
                std::cout << " [SIGNED]";
            } else if (proc.exePath) {
                std::cout << " [❌ UNSIGNED / FORGED!]";
            }

            if (proc.exePath) {
                std::cout << " -> " << *proc.exePath;
            } else {
                std::cout << " -> [ACCESS DENIED / SYSTEM]";
            }
            std::cout << "\n";
        }
        std::cout << "--------------------------------------------------\n";
        std::cout << "Total processes extracted: " << procs.size() << "\n\n";
    }

    void printPersistence(const std::vector<models::PersistenceEntry>& autostarts)
    {
        std::cout << "Starting Persistence Scan (Registry Run keys)...\n";
        std::cout << "--------------------------------------------------\n";
        for (const auto& entry : autostarts)
        {
            std::cout << "[" << entry.trigger << "]\t" << entry.name << " -> " << entry.imagePath << "\n";
        }
        std::cout << "--------------------------------------------------\n";
        std::cout << "Total persistence elements found: " << autostarts.size() << "\n\n";
    }

    void printNetwork(const std::vector<models::NetworkConn>& connections)
    {
        std::cout << "Starting Network Connection Scan (TCP IPv4)...\n";
        std::cout << "--------------------------------------------------\n";
        for (const auto& conn : connections)
        {
            std::string stateStr = "UNKNOWN";
            if (conn.state == models::State::Listen) stateStr = "LISTEN";
            else if (conn.state == models::State::Established) stateStr = "ESTABLISHED";
            else if (conn.state == models::State::TimeWait) stateStr = "TIME_WAIT";
            else if (conn.state == models::State::CloseWait) stateStr = "CLOSE_WAIT";

            std::cout << "[PID: " << (conn.ownerPid ? *conn.ownerPid : 0) << "]\t"
                      << conn.localAddr << ":" << conn.localPort << " -> "
                      << conn.remoteAddr << ":" << conn.remotePort << " [" << stateStr << "]\n";
        }
        std::cout << "--------------------------------------------------\n";
        std::cout << "Total network connections found: " << connections.size() << "\n\n";
    }

    void printServices(const std::vector<models::ServiceInfo>& services)
    {
        std::cout << "Starting Windows Services & Kernel Drivers Scan...\n";
        std::cout << "--------------------------------------------------\n";
        for (const auto& s : services)
        {
            // Only output services that have an image path on disk
            if (!s.imagePath.empty()) {
                std::cout << "[" << s.serviceType << "]\t" << s.name << " (" << s.displayName << ") -> " << s.imagePath << "\n";
            }
        }
        std::cout << "--------------------------------------------------\n";
        std::cout << "Total services/drivers audited: " << services.size() << "\n\n";
    }

    void printDigitalFootprint(const models::DigitalFootprint& footprint)
    {
        std::cout << "Starting Digital Footprint & Forensic Artifacts Extraction...\n";
        std::cout << "--------------------------------------------------\n";
        
        std::cout << "[Network Anonymity Status]:\n";
        std::cout << "  -> Active Proxy: " << (footprint.anonymity.isProxyActive ? "YES ⚠️" : "NO") << "\n";
        std::cout << "  -> Active VPN:   " << (footprint.anonymity.isVpnActive ? "YES ⚠️ (" + footprint.anonymity.activeAdapters + ")" : "NO") << "\n\n";

        std::cout << "[Extracted GPS Location]:\n";
        std::cout << "  -> Latitude:  " << footprint.location.latitude << "\n";
        std::cout << "  -> Longitude: " << footprint.location.longitude << "\n";
        std::cout << "  -> Source:    " << footprint.location.source << "\n\n";

        std::cout << "[USB Connection History (USBSTOR Check)]:\n";
        if (footprint.usbHistory.empty()) {
            std::cout << "  No USB storage devices found in registry logs.\n";
        } else {
            for (const auto& usb : footprint.usbHistory) {
                std::cout << "  -> " << usb.friendlyName << " [S/N: " << usb.deviceInstanceId << "]\n";
            }
        }
        std::cout << "--------------------------------------------------\n";
        std::cout << "Total USB devices extracted from registry: " << footprint.usbHistory.size() << "\n\n";
    
        std::cout << "[UserActivity History (UserAssist Execution Time Analysis)]:\n";
        for (const auto& ua : footprint.userActivity) {
            std::cout << "  -> Program: " << ua.programPath << "\n";
            std::cout << "     Launches: " << ua.runCount << " times | Total Active Focus Time: " << ua.totalActiveMinutes << " minutes\n";
        }
        std::cout << "\n";

        std::cout << "[Extracted OS Environment Data]:\n";
        std::cout << "  -> Operating System: " << footprint.osInformation.osName << "\n";
        std::cout << "  -> OS Install Date:  " << footprint.osInformation.installDate << "\n";
        std::cout << "  -> System Boot Time: " << footprint.osInformation.bootTime << "\n\n";

        std::cout << "[Mozilla Firefox History Tracking]:\n";
        if (footprint.browserHistory.empty()) {
            std::cout << "  No Firefox profile or history artifacts detected.\n";
        } else {
            for (const auto& b : footprint.browserHistory) {
                std::cout << "  -> Artifact: " << b.title << "\n";
                std::cout << "     Database: " << b.url << "\n";
                std::cout << "     Last User Activity (File Write): " << b.lastVisitTime << "\n";
            }
        }
        std::cout << "\n";

        std::cout << "[Extracted Bluetooth Paired Devices History]:\n";
        if (footprint.bluetoothHistory.empty()) {
            std::cout << "  No paired Bluetooth hardware logs found in registry.\n";
        } else {
            for (const auto& b : footprint.bluetoothHistory) {
                std::cout << "  -> Device Name: " << b.name << " (MAC: " << b.macAddress << ")\n";
            }
        }
        std::cout << "\n";
    }
}

int main(int argc, char* argv[]) 
{
    std::cout << "=== Fast Forensic Triage Extractor [Init] ===\n";
    std::cout << "Detected Platform: " << ff::kPlatformName << "\n\n";
    
    // Default path for the report file
    std::string jsonPath = "forensic_report.json";

    // Handle command line arguments (Custom CLI logic)
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if ((arg == "-o" || arg == "--output") && i + 1 < argc)
        {
            jsonPath = argv[++i]; // Take the next argument as the file path
        }
    }

    // 1. Create a scanner through the Factory
    std::unique_ptr<ff::core::ISystemScanner> scanner = ff::createScanner();
    
    if (!scanner)
    {
        std::cerr << "Error: Scanner for this platform is not implemented yet!\n";
        return 1;
    }

    std::cout << "Using " << scanner->platformName() << " scanner backend.\n\n";

    try 
    {
        // 2. Processes
        std::vector<ff::models::ProcessInfo> procs = scanner->scanProcesses();
        ff::printProcesses(procs);

        // 3. Autostarts / Persistence
        std::vector<ff::models::PersistenceEntry> autostarts = scanner->scanPersistence();
        ff::printPersistence(autostarts);

        // 4. Network table (IPv4 + IPv6)
        std::vector<ff::models::NetworkConn> connections = scanner->scanNetwork();
        ff::printNetwork(connections);

        // 5. Services and drivers
        std::vector<ff::models::ServiceInfo> services = scanner->scanServices();
        ff::printServices(services);

        // 6. Digital footprint (USB, GPS, VPN)
        ff::models::DigitalFootprint footprint = scanner->scanDigitalFootprint();
        ff::printDigitalFootprint(footprint);

        // 7. Export to JSON
        std::cout << "Generating unified forensic JSON report...\n";
        bool exportSuccess = ff::core::Exporter::saveToJson(
            jsonPath, procs, autostarts, connections, services, footprint
        );

        if (exportSuccess)
        {
            std::cout << "[SUCCESS] Forensic triage report saved to: " << jsonPath << "\n";
        }
        else
        {
            std::cerr << "[ERROR] Failed to write forensic report to disk!\n";
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "Scan failed with error: " << ex.what() << "\n";
        return 1;
    }
    
    return 0;
}