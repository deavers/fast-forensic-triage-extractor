#pragma once
#include "ff/Platform.h"

#ifdef FF_PLATFORM_WINDOWS
#include "ff/core/IArtifactSubScanner.h"
#include <vector>
#include <memory>

namespace ff::windows
{
    class WinRegistry
    {
    public:
        static void registerScanner(std::unique_ptr<core::IArtifactSubScanner> scanner) noexcept;
        static const std::vector<std::unique_ptr<core::IArtifactSubScanner>>& getScanners() noexcept;
    };

    // Macro for automatic initialization of Windows plugins before main() starts
    #define REGISTER_WINDOWS_ARTIFACT(ClassName) \
        static bool ClassName##_registered = []() noexcept { \
            ff::windows::WinRegistry::registerScanner(std::make_unique<ClassName>()); \
            return true; \
        }();
}
#endif