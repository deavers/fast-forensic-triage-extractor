#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <filesystem>
#include <string>
#include <sys/stat.h>

namespace ff::windows
{
    class PrefetchScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::error_code ec;
            std::string pfPath = "C:\\Windows\\Prefetch";
            
            // Prefetch folder is protected and may require admin privileges
            // If access is denied, std::filesystem will set an error code in 'ec'.
            if (std::filesystem::exists(pfPath, ec))
            {
                int count = 0;
                for (const auto& entry : std::filesystem::directory_iterator(pfPath, ec))
                {
                    // We only care about .pf files which are the actual prefetch files
                    if (entry.is_regular_file(ec) && entry.path().extension() == ".pf")
                    {
                        models::PrefetchEntry pf;
                        pf.prefetchFileName = entry.path().filename().string();
                        
                        // File name usually looks like: CMD.EXE-0A75225E.pf
                        // We extract the original name (before the dash)
                        size_t dashPos = pf.prefetchFileName.find_last_of('-');
                        if (dashPos != std::string::npos) 
                        {
                            pf.executableName = pf.prefetchFileName.substr(0, dashPos);
                        } 
                        else 
                        {
                            pf.executableName = pf.prefetchFileName;
                        }
                        
                        // Getting last run time from the file's last modified timestamp
                        struct stat fileStat;
                        if (stat(entry.path().string().c_str(), &fileStat) == 0)
                        {
                            char timeBuf[64];
                            if (std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&fileStat.st_mtime))) 
                            {
                                pf.lastRunTime = timeBuf;
                            }
                        }
                        else
                        {
                            pf.lastRunTime = "Unknown";
                        }
                        
                        footprint.prefetchFiles.push_back(std::move(pf));
                        
                        // Limit top 15 entries for demo report
                        if (count++ > 15) 
                            break; 
                    }
                }
            }
        }
    };

    // Registering plugin with Windows autopilot
    REGISTER_WINDOWS_ARTIFACT(PrefetchScanner)
}
#endif