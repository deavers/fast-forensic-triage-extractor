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
        // Here the functions will give their pointers themselves
        static void registerScanner(std::unique_ptr<core::IArtifactSubScanner> scanner) noexcept;
        
        // Get the entire list of registered artifact scanners
        static const std::vector<std::unique_ptr<core::IArtifactSubScanner>>& getScanners() noexcept;
    };

    // Clever macro for automatic registration
    #define REGISTER_LINUX_ARTIFACT(ClassName) \
        static bool ClassName##_registered = []() noexcept { \
            ff::linux_os::LinuxRegistry::registerScanner(std::make_unique<ClassName>()); \
            return true; \
        }();
}
#endif