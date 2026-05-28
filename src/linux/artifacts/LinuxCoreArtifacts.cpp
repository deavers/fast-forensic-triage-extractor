#ifdef FF_PLATFORM_LINUX
#include "src/linux/LinuxRegistry.h"
#include <fstream>
#include <sstream>

namespace ff::linux_os
{
    // Izolated sub-scanner for core Linux artifacts (e.g., loaded kernel modules)
    class LinuxCoreArtifacts : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // Direct reading of the Linux kernel file without layers
            std::ifstream modulesFile("/proc/modules");
            if (modulesFile.is_open())
            {
                std::string line;
                uint32_t counter = 0;
                
                // Read the first 10 modules to reveal the architecture
                while (std::getline(modulesFile, line) && counter++ < 10)
                {
                    std::istringstream iss(line);
                    std::string modName, modSize, modUses, modState;
                    if (iss >> modName >> modSize >> modUses >> modState)
                    {
                        // Load clean forensic data into the report
                        footprint.installedSoftware.push_back(
                            "[Kernel Driver LKM] " + modName + " (Size: " + modSize + " bytes)"
                        );
                    }
                }
                modulesFile.close();
            }
        }
    };

    // We pass the class name to the macro. When the OS application starts, 
    // it will call the constructor and put this class in the autopilot vector!
    REGISTER_LINUX_ARTIFACT(LinuxCoreArtifacts)
}
#endif