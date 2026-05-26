#pragma once
#include <string>

#include "ff/utils/json.hpp"

namespace ff::models
{
    struct ServiceInfo
    {
        std::string name;        // Service name (e.g., "YandexBrowserUpdate")
        std::string displayName; // User-friendly name
        std::string imagePath;   // Path to executable file (Driver or Service)
        std::string startType;   // How Starts: Automatic, Manual, Disabled
        std::string serviceType; // Type: Win32 Service or Kernel Driver (rootkit!)
    };

    // Serialization for JSON export
    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ServiceInfo, name, displayName, imagePath, startType, serviceType)
}