#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <filesystem>
#include <string>

namespace ff::linux_os
{
    class SystemdScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::error_code ec;
            std::string wantsPath = "/etc/systemd/system/multi-user.target.wants";
            
            if (std::filesystem::exists(wantsPath, ec))
            {
                int count = 0;

                for (const auto& entry : std::filesystem::directory_iterator(wantsPath, ec))
                {
                    models::SystemdUnit unit;
                    unit.name = entry.path().filename().string();
                    unit.state = "enabled"; // If a symlink exists here, the service is enabled
                    
                    footprint.systemdUnits.push_back(std::move(unit));
                    
                    if (count++ > 20) 
                        break; // Limit for demo report
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(SystemdScanner)
}
#endif