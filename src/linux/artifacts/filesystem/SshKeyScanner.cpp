#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <fstream>
#include <filesystem>
#include <cstdlib>

namespace ff::linux_os
{
    class SshKeyScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::vector<std::string> targets = { "/root/.ssh/authorized_keys" };
            if (const char* home = std::getenv("HOME"))
            {
                targets.push_back(std::string(home) + "/.ssh/authorized_keys");
            }

            for (const auto& path : targets)
            {
                if (std::filesystem::exists(path))
                {
                    std::ifstream sshFile(path);
                    std::string line;
                    while (std::getline(sshFile, line))
                    {
                        if (line.empty() || line[0] == '#') continue;
                        
                        models::SshKeyEntry key;
                        key.path = path;
                        key.keyContent = line.substr(0, 30) + "..."; 
                        footprint.sshKeys.push_back(std::move(key));
                    }
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(SshKeyScanner)
}
#endif