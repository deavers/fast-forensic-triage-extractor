#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <filesystem>
#include <string>
#include <algorithm>

namespace ff::linux_os
{
    class ProcFdScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::error_code ec;
            std::filesystem::directory_iterator it("/proc", ec);
            const std::filesystem::directory_iterator end;

            for (; !ec && it != end; it.increment(ec))
            {
                std::error_code entryEc;
                const auto& entry = *it;

                if (!entry.is_directory(entryEc))
                    continue;

                std::string pidStr = entry.path().filename().string();

                if (!std::all_of(pidStr.begin(), pidStr.end(), ::isdigit))
                    continue;

                std::string fdPath = entry.path().string() + "/fd";
                std::string openFilesStr;

                std::filesystem::directory_iterator fdIt(fdPath, entryEc);
                for (; !entryEc && fdIt != end; fdIt.increment(entryEc))
                {
                    std::error_code linkEc;
                    auto target = std::filesystem::read_symlink(fdIt->path(), linkEc);
                    if (!linkEc)
                        openFilesStr += target.string() + "; ";
                }

                if (!openFilesStr.empty())
                {
                    models::ProcFdEntry fdResult;
                    fdResult.pid = pidStr;
                    fdResult.openFiles = openFilesStr;
                    footprint.processFileDescriptors.push_back(std::move(fdResult));
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(ProcFdScanner)
}
#endif