#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <filesystem>
#include <string>
#include <algorithm>
#include <vector>

namespace ff::linux_os
{
    class SystemdScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::error_code ec;
            std::filesystem::directory_iterator it(
                "/etc/systemd/system/multi-user.target.wants", ec);
            const std::filesystem::directory_iterator end;

            std::vector<std::string> names;
            for (; !ec && it != end; it.increment(ec))
                names.push_back(it->path().filename().string());

            std::sort(names.begin(), names.end());

            for (auto& name : names)
            {
                models::SystemdUnit unit;
                unit.name = std::move(name);
                unit.state = "enabled"; // If a symlink exists here, the service is enabled
                footprint.systemdUnits.push_back(std::move(unit));
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(SystemdScanner)
}
#endif