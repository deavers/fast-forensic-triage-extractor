#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <filesystem>
#include <string>
#include <algorithm>

namespace ff::linux_os
{
    class ProcFdScanner : public core::IArtifactSubScanner
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

                std::string fdPath = entry.path().string() + "/fd";
                std::string openFilesStr = "";
                int count = 0;
                
                // We check if we have permission to read the file descriptors of this process
                if (std::filesystem::exists(fdPath, ec))
                {
                    for (const auto& fdEntry : std::filesystem::directory_iterator(fdPath, ec))
                    {
                        // Take only first 5 for our report
                        if (count++ > 5) 
                        { 
                            openFilesStr += "...";
                            break;
                        }
                        
                        // We read where the symbolic link points to (the actual path to the file)
                        openFilesStr += std::filesystem::read_symlink(fdEntry.path(), ec).string() + "; ";
                    }
                    
                    if (!openFilesStr.empty())
                    {
                        models::ProcFdEntry fdResult;
                        fdResult.pid = pidStr;
                        fdResult.openFiles = openFilesStr;
                        footprint.processFileDescriptors.push_back(std::move(fdResult));
                    }
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(ProcFdScanner)
}
#endif