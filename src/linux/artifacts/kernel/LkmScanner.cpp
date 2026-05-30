#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <fstream>
#include <sstream>

namespace ff::linux_os
{
    class LkmScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::ifstream modulesFile("/proc/modules");
            if (modulesFile.is_open())
            {
                std::string line;
                uint32_t limit = 0;
                while (std::getline(modulesFile, line) && limit++ < 15)
                {
                    std::istringstream iss(line);
                    models::KernelModule mod;
                    std::string dummyUses;
                    
                    // Format: name size uses state ...
                    if (iss >> mod.name >> mod.size >> dummyUses >> mod.state)
                    {
                        footprint.linuxModules.push_back(std::move(mod));
                    }
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(LkmScanner)
}
#endif