#include "ff/Platform.h"
#include "WinRegistry.h"

#ifdef FF_PLATFORM_WINDOWS


namespace ff::windows
{
    static std::vector<std::unique_ptr<core::IArtifactSubScanner>> g_winRegistry;

    void WinRegistry::registerScanner(std::unique_ptr<core::IArtifactSubScanner> scanner) noexcept
    {
        g_winRegistry.push_back(std::move(scanner));
    }

    const std::vector<std::unique_ptr<core::IArtifactSubScanner>>& WinRegistry::getScanners() noexcept
    {
        return g_winRegistry;
    }
}
#endif