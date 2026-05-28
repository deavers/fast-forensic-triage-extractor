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

        // 2. Call platform-specific output modules
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

    // LINUX-SPECIFIC OUTPUT (FUNCTIONS 30,34)
    void ConsolePrinter::printLinuxSpecifics(const models::DigitalFootprint& footprint)
    {
        #if defined(FF_PLATFORM_LINUX)
            if (!footprint.linuxModules.empty()) 
            {
                std::cout << "[Linux Resident Kernel Modules (LKM - Function 30)]:\n";
                for (const auto& mod : footprint.linuxModules) 
                {
                    std::cout << "  -> Module: " << mod.name << " | Size: " << mod.size << " bytes | State: " << mod.state << "\n";
                }
                std::cout << "\n";
            }

            if (!footprint.sshKeys.empty()) 
            {
                std::cout << "[Linux Remote Access Artifacts (SSH Keys - Function 34)]:\n";
                for (const auto& key : footprint.sshKeys) 
                {
                    std::cout << "  -> File: " << key.path << " | Snapshot: " << key.keyContent << "\n";
                }
                std::cout << "\n";
            }
        #else
            // Professionally silencing the unused parameter warning on Windows
            (void)footprint; 
        #endif
    }

    // WINDOWS-SPECIFIC OUTPUT (FUNCTIONS 32,33)
    void ConsolePrinter::printWindowsSpecifics(const models::DigitalFootprint& footprint)
    {
        #if defined(FF_PLATFORM_WINDOWS)
            if (!footprint.arpEntries.empty()) 
            {
                std::cout << "[Windows Kernel ARP Table (Function 32)]:\n";
                for (const auto& arp : footprint.arpEntries) 
                {
                    std::cout << "  -> IP: " << arp.ipAddress << " \tMAC: " << arp.macAddress << " [" << arp.type << "]\n";
                }
                std::cout << "\n";
            }

            if (!footprint.firewallRules.empty()) 
            {
                std::cout << "[Windows Active Firewall Rules Triage (Function 33)]:\n";
                for (const auto& rule : footprint.firewallRules) 
                {
                    std::cout << "  -> Rule: " << rule.ruleName << "\n";
                }
                std::cout << "\n";
            }
        #else
            // Professionally silencing the unused parameter warning on Linux
            (void)footprint; 
        #endif
    }
}