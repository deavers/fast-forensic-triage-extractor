#pragma once
#include "ff/models/ForensicArtifacts.h"
#include <string_view>

namespace ff::core
{
    enum class ScanMode { UnPrivileged, Elevated };

    class ISystemScanner
    {
    public:
        virtual ~ISystemScanner() = default;
        virtual std::string_view platformName() const = 0;
        virtual models::DigitalFootprint scanDigitalFootprint() = 0;
    };
}