#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <fstream>
#include <string>

namespace ff::linux_os
{
    class PkgScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::ifstream dpkgFile("/var/lib/dpkg/status");
            
            if (dpkgFile.is_open())
            {
                std::string line;
                models::PkgInfo currentPkg;
                int count = 0;

                while (std::getline(dpkgFile, line))
                {
                    if (line.find("Package: ") == 0) 
                    {
                        currentPkg.name = line.substr(9);
                    }
                    else if (line.find("Version: ") == 0) 
                    {
                        currentPkg.version = line.substr(9);

                        if (!currentPkg.name.empty()) 
                        {
                            // Add the completed package info to the footprint
                            footprint.installedPackages.push_back(currentPkg);
                            currentPkg = models::PkgInfo(); // Reset for next package

                            if (count++ > 50) 
                                break; // Limiting for demo report
                        }
                    }
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(PkgScanner)
}
#endif