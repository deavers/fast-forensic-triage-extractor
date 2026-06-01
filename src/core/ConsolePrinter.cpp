#include "ff/utils/ConsolePrinter.h"
#include "ff/Platform.h"
#include <iostream>
#include <string>

namespace ff::utils
{
    // MAIN ENTRY POINT
    void ConsolePrinter::printForensicReport(const models::DigitalFootprint& footprint)
    {
        std::cout << "==================================================\n";
        std::cout << "  DIGITAL FOOTPRINT & AUTOPILOT PLUGINS REPORT\n";
        std::cout << "==================================================\n";
        
        // Print common data for both platforms
        printCommonData(footprint);

        // Call platform-specific output modules
        #if defined(FF_PLATFORM_LINUX)
            printLinuxSpecifics(footprint);
        #elif defined(FF_PLATFORM_WINDOWS)
            printWindowsSpecifics(footprint);
        #endif

        std::cout << "==================================================\n";
    }

    // BOTH PLATFORMS - COMMON DATA OUTPUT
    void ConsolePrinter::printCommonData(const models::DigitalFootprint& footprint)
    {
        std::cout << "[Extracted Hardware Triage (WMI)]:\n";
        std::cout << "  -> CPU: " << footprint.hw_info.cpuName << "\n";
        std::cout << "  -> GPU: " << footprint.hw_info.gpuName << "\n";
        std::cout << "  -> RAM: " << footprint.hw_info.totalRamGB << "\n";
        std::cout << "  -> SMBIOS Serial: " << footprint.hw_info.motherboardSerial << "\n\n";

        std::cout << "[Extracted OS Environment Data]:\n";
        std::cout << "  -> Operating System: " << footprint.osInformation.osName << "\n";
        std::cout << "  -> OS Install Date:  " << footprint.osInformation.installDate << "\n";
        std::cout << "  -> System Boot Time: " << footprint.osInformation.bootTime << "\n\n";

        std::cout << "[Extracted GPS Location Triage]:\n";
        std::cout << "  -> Latitude:  " << footprint.location.latitude << "\n";
        std::cout << "  -> Longitude: " << footprint.location.longitude << "\n";
        std::cout << "  -> Source:    " << footprint.location.source << "\n\n";

        if (!footprint.installedSoftware.empty()) 
        {
            std::cout << "[Active Software & Low-Level Process Tracking]:\n";
            for (const auto& sw : footprint.installedSoftware) 
            {
                std::cout << "  -> " << sw << "\n";
            }
            std::cout << "\n";
        }

        if (!footprint.hostsLines.empty()) 
        {
            std::cout << "[Network Socket Bindings & Hosts Interceptions]:\n";
            for (const auto& hl : footprint.hostsLines) 
            {
                std::cout << "  -> " << hl << "\n";
            }
            std::cout << "\n";
        }
    }

    // LINUX-SPECIFIC OUTPUT
    void ConsolePrinter::printLinuxSpecifics(const models::DigitalFootprint& footprint)
    {
        #if defined(FF_PLATFORM_LINUX)
            if (!footprint.linuxModules.empty()) 
            {
                std::cout << "[Linux Resident Kernel Modules (LKM - Function 47)]:\n";
                for (const auto& mod : footprint.linuxModules) 
                {
                    std::cout << "  -> Module: " << mod.name << " | Size: " << mod.size << " bytes | State: " << mod.state << "\n";
                }
                std::cout << "\n";
            }

            if (!footprint.sshKeys.empty()) 
            {
                std::cout << "[Linux Remote Access Artifacts (SSH Keys - Function 56)]:\n";
                for (const auto& key : footprint.sshKeys) 
                {
                    std::cout << "  -> File: " << key.path << " | Snapshot: " << key.keyContent << "\n";
                }
                std::cout << "\n";
            }

            if (!footprint.processCredentials.empty())
            {
                std::cout << "\n[Linux Process Credentials (Function 50)]:\n";
                int count = 0;
                for (const auto& cred : footprint.processCredentials) 
                {
                    if (count++ > 5) { std::cout << "  ... (more processes hidden. See JSON.)\n"; break; }
                    std::cout << "  -> PID: " << cred.pid << " | UID: " << cred.uid_info << " | GID: " << cred.gid_info << "\n";
                }
            }

            if (!footprint.processFileDescriptors.empty())
            {
                std::cout << "\n[Linux Open File Descriptors (Function 48)]:\n";
                int count = 0;
                for (const auto& fd : footprint.processFileDescriptors) 
                {
                    if (count++ > 5) break;
                    std::cout << "  -> PID: " << fd.pid << " | Open FDs: " << fd.openFiles << "\n";
                }
            }

            if (!footprint.processEnvironments.empty())
            {
                std::cout << "\n[Linux Process Environment Variables (Function 49)]:\n";
                int count = 0;
                for (const auto& env : footprint.processEnvironments)
                 {
                    if (count++ > 5) break;
                    std::cout << "  -> PID: " << env.pid << " | ENV: " << env.envDump << "\n";
                }
            }

            if (!footprint.processCgroups.empty())
            {
                std::cout << "\n[Linux Container Isolation Triage (Function 51)]:\n";
                for (const auto& cg : footprint.processCgroups) 
                {
                    std::cout << "  -> PID: " << cg.pid << " | Container: " << cg.containerPath << "\n";
                }
            }
            
            if (!footprint.installedPackages.empty())
            {
                std::cout << "\n[Linux Installed Packages Inventory (Function 52)]:\n";
                int count = 0;
                for (const auto& pkg : footprint.installedPackages) {
                    if (count++ > 10) break;
                    std::cout << "  -> Package: " << pkg.name << " | Version: " << pkg.version << "\n";
                }
            }
        #else
            // Professionally silencing the unused parameter warning on Windows
            (void)footprint; 
        #endif
    }

    // WINDOWS-SPECIFIC OUTPUT
    void ConsolePrinter::printWindowsSpecifics(const models::DigitalFootprint& footprint)
    {
        #if defined(FF_PLATFORM_WINDOWS)
            // SYSTEM FILES
            if (!footprint.systemFiles.empty()) 
            {
                std::cout << "[Windows Hidden System Files (RAM Dumps)]:\n";
                for (const auto& sf : footprint.systemFiles) 
                {
                    std::cout << "  -> File: " << sf.fileName << " | Size: " << sf.sizeMB << "\n";
                }
                std::cout << "\n";
            }

            // WEB & BROWSER (Grouped History, Extensions, DNS)
            if (!footprint.browserHistory.empty() || !footprint.browserExtensions.empty() || !footprint.dnsCache.empty()) {
                std::cout << "[Windows Web & Browser Triage (History, Extensions, DNS)]:\n";
                
                int histCount = 0;
                for (const auto& bh : footprint.browserHistory) 
                {
                    if (histCount++ > 5) break;
                    std::cout << "  -> [History] " << bh.url << " | Last Visit: " << bh.lastVisitTime << "\n";
                }
                
                for (const auto& ext : footprint.browserExtensions) 
                {
                    std::cout << "  -> [Extension] " << ext.browser << " | ID: " << ext.extensionId << "\n";
                }

                int dnsCount = 0;
                for (const auto& dns : footprint.dnsCache) 
                {
                    if (dnsCount++ > 8) { std::cout << "  ... (more DNS records hidden. See JSON.)\n"; break; }
                    std::cout << "  -> [DNS Cache] " << dns.recordName << " -> " << dns.data << "\n";
                }
            }

            // NETWORK
            if (!footprint.networkConnections.empty()) 
            {
                std::cout << "\n[Windows Network Connections Triage]:\n";
                int count = 0;
                for (const auto& conn : footprint.networkConnections) 
                {
                    if (count++ > 10) 
                        break;

                    std::cout << "  -> [" << conn.protocol << "] " << conn.localIp << ":" << conn.localPort 
                              << " --> " << conn.remoteIp << ":" << conn.remotePort << " | State: " << conn.state << "\n";
                }
            }

            // MEMORY ANOMALIES
            if (!footprint.injectedMemory.empty()) 
            {
                std::cout << "\n[Windows Process Memory Anomalies (Injected DLL / Shellcode)]:\n";
                for (const auto& mem : footprint.injectedMemory)
                {
                    std::cout << "  [!] ALERT -> Process: " << mem.processName << " (PID: " << mem.pid 
                              << ") | Memory at " << mem.memoryAddress << " [" << mem.protection << "]\n";
                }
            }

            // EVENT LOGS & CLIPBOARD
            if (!footprint.eventLogs.empty()) 
            {
                std::cout << "\n[Windows Event Log Security Triage]:\n";
                for (const auto& evt : footprint.eventLogs) 
                {
                    std::cout << "  -> Event: " << evt.eventId << " | Time: " << evt.timestamp << " | " << evt.details << "\n";
                }
            }

            if (!footprint.clipboardData.empty()) 
            {
                std::cout << "\n[Windows Live Clipboard Triage (Data Exfiltration Risk)]:\n";
                for (const auto& clip : footprint.clipboardData) 
                {
                    std::cout << "  [!] CLIPPED DATA -> Format: " << clip.format << " | Size: " << clip.sizeBytes << "\n";
                }
            }
        #else
            (void)footprint; 
        #endif
    }
}