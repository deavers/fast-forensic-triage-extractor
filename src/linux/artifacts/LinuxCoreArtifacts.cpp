#ifdef FF_PLATFORM_LINUX
#include "src/linux/LinuxRegistry.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdlib>

namespace ff::linux_os
{
    class LinuxCoreArtifacts : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // --- Function 30: Honest parsing of kernel modules LKM ---
            std::ifstream modulesFile("/proc/modules");
            if (modulesFile.is_open())
            {
                std::string line;
                while (std::getline(modulesFile, line))
                {
                    std::istringstream iss(line);
                    std::string modName, modSize, modUses, modState;
                    if (iss >> modName >> modSize >> modUses >> modState)
                    {
                        models::KernelModule mod;
                        mod.name = std::move(modName);
                        mod.size = std::move(modSize);
                        mod.state = std::move(modState);
                        footprint.linuxModules.push_back(std::move(mod));
                    }
                }
                modulesFile.close();
            }

            // --- Function 34: Scanning of SSH authorized keys ---
            std::vector<std::string> sshPaths = { "/root/.ssh/authorized_keys" };
            const char* homeEnv = std::getenv("HOME");
            if (homeEnv) {
                sshPaths.push_back(std::string(homeEnv) + "/.ssh/authorized_keys");
            }

            for (const auto& path : sshPaths)
            {
                if (std::filesystem::exists(path))
                {
                    std::ifstream file(path);
                    if (file.is_open())
                    {
                        std::string line;
                        while (std::getline(file, line))
                        {
                            if (line.empty() || line[0] == '#') continue;
                            
                            models::SshKeyEntry key;
                            key.path = path;
                            key.keyContent = line; // Public key 
                            footprint.sshKeys.push_back(std::move(key));
                        }
                        file.close();
                    }
                }
            }
        }
    };

    // Auto-register this artifact scanner in the Linux registry
    REGISTER_LINUX_ARTIFACT(LinuxCoreArtifacts)
}
#endif