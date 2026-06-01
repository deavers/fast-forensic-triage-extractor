#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <fstream>
#include <string>

namespace ff::windows
{
    class HostsFileScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // Getting system path (C:\Windows\System32)
            char sysDir[MAX_PATH];
            if (!GetSystemDirectoryA(sysDir, MAX_PATH)) 
                return;

            std::string hostsPath = std::string(sysDir) + "\\drivers\\etc\\hosts";
            std::ifstream file(hostsPath);

            if (file.is_open())
            {
                std::string line;
                while (std::getline(file, line))
                {
                    // Trimming whitespace from the line
                    line.erase(0, line.find_first_not_of(" \t\r\n"));
                    line.erase(line.find_last_not_of(" \t\r\n") + 1);

                    // Skipping empty lines and comments
                    if (line.empty() || line[0] == '#') 
                        continue;

                    // Active DNS override found, adding to footprint
                    footprint.hostsLines.push_back("DNS Override: " + line);
                }
                file.close();
            }
        }
    };

    // Autopilot
    REGISTER_WINDOWS_ARTIFACT(HostsFileScanner)
}
#endif