#ifdef FF_PLATFORM_LINUX
#include "LinuxRegistry.h"

namespace ff::linux_os
{
    static std::vector<std::unique_ptr<core::IArtifactSubScanner>> g_linuxRegistry;

    void LinuxRegistry::registerScanner(std::unique_ptr<core::IArtifactSubScanner> scanner) noexcept
    {
        g_linuxRegistry.push_back(std::move(scanner));
    }

    const std::vector<std::unique_ptr<core::IArtifactSubScanner>>& LinuxRegistry::getScanners() noexcept
    {
        return g_linuxRegistry;
    }
}
#endif