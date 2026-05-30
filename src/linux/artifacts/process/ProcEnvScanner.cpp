#include "ff/Platform.h"

#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <filesystem>
#include <fstream>
#include <string>
#include <algorithm>

namespace ff::linux_os
{
    class ProcEnvScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // We iterate through all process folders in /proc
            for (const auto& entry : std::filesystem::directory_iterator("/proc"))
            {
                if (!entry.is_directory()) continue;
                
                std::string pidStr = entry.path().filename().string();
                
                // We check that the folder contains only digits (this is a PID)
                if (!std::all_of(pidStr.begin(), pidStr.end(), ::isdigit)) continue;

                std::string envPath = entry.path().string() + "/environ";
                std::ifstream envFile(envPath, std::ios::binary);
                
                if (envFile)
                {
                    std::string envData((std::istreambuf_iterator<char>(envFile)), std::istreambuf_iterator<char>());
                    
                    // In Linux, variables are separated by null bytes '\0', we replace them with spaces for readability
                    for (char& c : envData) 
                    {
                        if (c == '\0') 
                            c = ' ';
                    }
                    
                    if (!envData.empty())
                    {
                        models::ProcEnvEntry envEntry;
                        envEntry.pid = pidStr;
                        // In Linux, we only take the first 100 characters to avoid filling up RAM with garbage
                        envEntry.envDump = envData.substr(0, 100) + "..."; 
                        footprint.processEnvironments.push_back(std::move(envEntry));
                    }
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(ProcEnvScanner)
}
#endif