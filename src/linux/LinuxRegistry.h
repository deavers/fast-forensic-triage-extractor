#pragma once
#ifdef FF_PLATFORM_LINUX
#include "ff/core/IArtifactSubScanner.h"
#include <vector>
#include <memory>

namespace ff::linux_os
{
    class LinuxRegistry
    {
    public:
        static void registerScanner(std::unique_ptr<core::IArtifactSubScanner> scanner) noexcept;
        static const std::vector<std::unique_ptr<core::IArtifactSubScanner>>& getScanners() noexcept;
    };

    #define REGISTER_LINUX_ARTIFACT(ClassName) \
        static bool ClassName##_registered = []() noexcept { \
            ff::linux_os::LinuxRegistry::registerScanner(std::make_unique<ClassName>()); \
            return true; \
        }();
}
#endif