#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <filesystem>
#include <fstream>
#include <string>
#include <algorithm>

namespace ff::linux_os
{
    class ProcCredScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::error_code ec;

            for (const auto& entry : std::filesystem::directory_iterator("/proc", ec))
            {
                if (!entry.is_directory(ec)) 
                    continue;
                
                std::string pidStr = entry.path().filename().string();

                if (!std::all_of(pidStr.begin(), pidStr.end(), ::isdigit)) 
                    continue;

                std::ifstream statusFile(entry.path().string() + "/status");
                if (statusFile)
                {
                    models::ProcCredEntry creds;
                    creds.pid = pidStr;
                    std::string line;
                    
                    while (std::getline(statusFile, line))
                    {
                        if (line.find("Uid:\t") == 0) 
                            creds.uid_info = line.substr(5);

                        if (line.find("Gid:\t") == 0) 
                            creds.gid_info = line.substr(5);
                    }
                    
                    if (!creds.uid_info.empty()) 
                        footprint.processCredentials.push_back(std::move(creds));
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(ProcCredScanner)
}
#endif