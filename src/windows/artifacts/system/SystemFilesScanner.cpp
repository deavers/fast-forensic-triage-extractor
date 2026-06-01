#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>

namespace ff::windows
{
    class SystemFilesScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            checkFile(footprint, "C:\\pagefile.sys", "Virtual Memory Paging File (RAM Swap)");
            checkFile(footprint, "C:\\hiberfil.sys", "System Hibernation File (Full RAM Dump)");
            checkFile(footprint, "C:\\swapfile.sys", "UWP Application Swap File");
        }

    private:
        // Helper function to check file existence and size, and add to footprint
        void checkFile(models::DigitalFootprint& footprint, const std::string& path, const std::string& note) const
        {
            WIN32_FIND_DATAA findData;
            HANDLE hFind = FindFirstFileA(path.c_str(), &findData);
            
            models::SystemFileEntry entry;
            entry.fileName = path;
            entry.notes = note;

            if (hFind != INVALID_HANDLE_VALUE)
            {
                ULARGE_INTEGER sz;
                sz.HighPart = findData.nFileSizeHigh;
                sz.LowPart = findData.nFileSizeLow;
                
                // Bytes to MB
                entry.sizeMB = std::to_string(sz.QuadPart / (1024 * 1024)) + " MB";
                FindClose(hFind);
            }
            else
            {
                entry.sizeMB = "Not Found / Inaccessible";
            }
            
            footprint.systemFiles.push_back(std::move(entry));
        }
    };

    REGISTER_WINDOWS_ARTIFACT(SystemFilesScanner)
}
#endif