#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <filesystem>
#include <fstream>
#include <string>
#include <algorithm>

namespace ff::linux_os
{
    class CgroupScanner : public core::IArtifactSubScanner
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

                std::ifstream cgroupFile(entry.path().string() + "/cgroup");

                if (cgroupFile)
                {
                    std::string line;
                    bool isDocker = false;
                    std::string cPath = "host";

                    while (std::getline(cgroupFile, line))
                    {
                        // If cgroup has docker, lxc or kubepods - it's a containerized process
                        if (line.find("/docker/") != std::string::npos || 
                            line.find("/lxc/") != std::string::npos)
                        {
                            isDocker = true;
                            cPath = line; // Container path
                            break;
                        }
                    }

                    models::ProcCgroupEntry cgEntry;
                    cgEntry.pid = pidStr;
                    cgEntry.containerPath = cPath;
                    cgEntry.isContainerized = isDocker;
                    
                    // Remove If to include all processes, even non-containerized ones
                    if (isDocker) 
                    {
                        footprint.processCgroups.push_back(std::move(cgEntry));
                    }
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(CgroupScanner)
}
#endif