#pragma once
#include "ff/core/ISystemScanner.h"

namespace ff::linux_os
{
    class LinuxSystemScanner final : public core::ISystemScanner
    {
    public:
        explicit LinuxSystemScanner(core::ScanMode mode);
        ~LinuxSystemScanner() noexcept override = default;

        // RAII - prevent copying
        LinuxSystemScanner(const LinuxSystemScanner&) = delete;
        LinuxSystemScanner& operator=(const LinuxSystemScanner&) = delete;

        std::string_view platformName() const override;
        
        models::DigitalFootprint scanDigitalFootprint() override;

    private:
        core::ScanMode m_mode;
    };
}