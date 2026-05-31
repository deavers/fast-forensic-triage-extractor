#pragma once
#include "ff/core/ISystemScanner.h"
#include "ff/models/ForensicArtifacts.h"

namespace ff::windows
{
    class WinSystemScanner : public core::ISystemScanner
    {
    public:
        explicit WinSystemScanner(core::ScanMode mode = core::ScanMode::UnPrivileged);
        [[nodiscard]] std::string_view platformName() const override;
        models::DigitalFootprint scanDigitalFootprint() override;

    private:
        core::ScanMode m_mode;
    };
}