#include "ff/core/ISystemScanner.h"
#include "ff/core/Exporter.h"
#include "ff/utils/ConsolePrinter.h"
#include "ff/Platform.h"

#if defined(FF_PLATFORM_WINDOWS)
    #include "windows/WinSystemScanner.h"
#elif defined(FF_PLATFORM_LINUX)
    #include "linux/LinuxSystemScanner.h"
#endif

#include <iostream>
#include <memory>
#include <string>

namespace ff
{
    std::unique_ptr<core::ISystemScanner> createScanner()
    {
        #if defined(FF_PLATFORM_WINDOWS)
            return std::make_unique<windows::WinSystemScanner>(core::ScanMode::Elevated);
        #elif defined(FF_PLATFORM_LINUX)
            return std::make_unique<::ff::linux_os::LinuxSystemScanner>(core::ScanMode::Elevated);
        #else
            return nullptr;
        #endif
    }
}

int main()
{
    std::cout << "=== Fast Forensic Triage Extractor (FFTE) [Init] ===\n";
    
    auto scanner = ff::createScanner();
    if (!scanner)
    {
        std::cerr << "[!] Error: Unsupported platform.\n";
        return 1;
    }

    std::cout << "Detected Local Platform Compilation: " << scanner->platformName() << "\n\n";
    std::cout << "Activating native " << scanner->platformName() << " triage core...\n\n";

    // Autopilot collection of the digital footprint
    auto footprint = scanner->scanDigitalFootprint();

    // Determine output file name based on platform
    #if defined(FF_PLATFORM_WINDOWS)
        std::string outputFileName = "forensics_report_windows.json";
    #elif defined(FF_PLATFORM_LINUX)
        std::string outputFileName = "forensics_report_linux.json";
    #else
        std::string outputFileName = "forensics_report_unknown.json";
    #endif

    // Save to JSON
    std::cout << "[*] Serializing consolidated forensics JSON log...\n";
    if (ff::core::Exporter::saveToJson(outputFileName, footprint)) 
        std::cout << "[SUCCESS] Forensic artifact session saved to: " << outputFileName << "\n\n";
    else 
        std::cerr << "[ERROR] Failed to write forensic report to disk.\n\n";
    
    // Print the report to console
    ff::utils::ConsolePrinter::printForensicReport(footprint);
    
    return 0;
}