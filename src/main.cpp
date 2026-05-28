#include <iostream>
#include <memory>
#include <vector>
#include <string>

#include "ff/Platform.h"
#include "ff/core/ISystemScanner.h"
#include "ff/models/ForensicArtifacts.h"
#include "ff/core/Exporter.h"
#include "ff/utils/ConsolePrinter.h"

// Cross-platforming
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
}

int main(int argc, char* argv[]) 
{
    std::cout << "=== Fast Forensic Triage Extractor (FFTE) [Init] ===\n";
    std::cout << "Detected Local Platform Compilation: " << ff::kPlatformName << "\n\n";
    
    // Default file name
    std::string jsonPath = "forensic_report.json";

    // CLI argument parsing for output file path (optional) (-o or --output)
    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];
        if ((arg == "-o" || arg == "--output") && i + 1 < argc)
        {
            jsonPath = argv[++i];
        }
    }

    // Platform scanner factory
    std::unique_ptr<ff::core::ISystemScanner> scanner = ff::createScanner();
    if (!scanner)
    {
        std::cerr << "[FATAL] Scanner backend for this platform is missing!\n";
        return 1;
    }

    std::cout << "Activating native " << scanner->platformName() << " triage core...\n\n";

    try 
    {
        // 1 - Collecting digital footprint with full autopilot plugins automation
        ff::models::DigitalFootprint footprint = scanner->scanDigitalFootprint();
        
        // 2 - Console report
        ff::utils::ConsolePrinter::printForensicReport(footprint);

        // 3 - Empty vectors for sections not implemented in this version
        std::vector<ff::models::ProcessInfo> emptyProcs;
        std::vector<ff::models::PersistenceEntry> emptyAutostarts;
        std::vector<ff::models::NetworkConn> emptyConnections;
        std::vector<ff::models::ServiceInfo> emptyServices;

        // 4 - Final JSON export
        std::cout << "Serializing consolidated forensics JSON log...\n";
        bool exportSuccess = ff::core::Exporter::saveToJson(
            jsonPath, emptyProcs, emptyAutostarts, emptyConnections, emptyServices, footprint
        );

        if (exportSuccess)
        {
            std::cout << "[SUCCESS] Forensic artifact session saved to: " << jsonPath << "\n";
        }
        else
        {
            std::cerr << "[ERROR] Write file permission error on: " << jsonPath << "\n";
        }
    }
    catch (const std::exception& ex)
    {
        std::cerr << "[FATAL CRASH] Pipeline broken: " << ex.what() << "\n";
        return 1;
    }
    
    return 0;
}