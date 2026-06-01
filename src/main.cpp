#include "ff/core/ISystemScanner.h"
#include "ff/core/Exporter.h"
#include "ff/utils/ConsolePrinter.h"
#include "ff/Platform.h"
#include <windows.h>

#if defined(FF_PLATFORM_WINDOWS)
    #include "windows/WinSystemScanner.h"
#elif defined(FF_PLATFORM_LINUX)
    #include "linux/LinuxSystemScanner.h"
#endif

#include <iostream>
#include <memory>

namespace ff
{
    std::unique_ptr<core::ISystemScanner> createScanner()
    {
        #if defined(FF_PLATFORM_WINDOWS)
            return std::make_unique<windows::WinSystemScanner>(core::ScanMode::Elevated);
        #elif defined(FF_PLATFORM_LINUX)
            return std::make_unique<linux::LinuxSystemScanner>(core::ScanMode::Elevated);
        #else
            return nullptr;
        #endif
    }
}

int main(int argc, char* argv[])
{
    (void)argc;
    (void)argv;

    // (ANTI-DEBUGGING & EVASION)
    #if defined(FF_PLATFORM_WINDOWS)
        // Check for common debuggers (x64dbg, OllyDbg)
        if (IsDebuggerPresent()) 
        {
            // Finish the program immediately if a debugger is detected to prevent analysis
            return 0; 
        }
        
        // 2. Check for remote debugging (IDA Pro Remote)
        BOOL isRemoteDebugger = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebugger) && isRemoteDebugger) 
        {
            // Finish the program immediately if a debugger is detected to prevent analysis
            return 0;
        }
    #endif

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

    // Save to JSON
    std::cout << "[*] Serializing consolidated forensics JSON log...\n";
    if (ff::core::Exporter::saveToJson("forensic_report.json", footprint)) 
        std::cout << "[SUCCESS] Forensic artifact session saved to: forensic_report.json\n\n";
    else 
        std::cerr << "[ERROR] Failed to write forensic report to disk.\n\n";
    
    // Print the report to console
    ff::utils::ConsolePrinter::printForensicReport(footprint);
    
    return 0;
}