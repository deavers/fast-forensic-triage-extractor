#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>

namespace ff::windows
{
    class ScheduledTaskScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            HKEY hKey; // Handle for the registry key

            // This registry branch contains the cache of all Windows scheduled tasks
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                enumTasks(hKey, "", footprint);
                RegCloseKey(hKey);
            }
        }

    private:
        // Recursively enumerates the registry tree to find all scheduled tasks
        void enumTasks(HKEY hKey, const std::string& currentPath, models::DigitalFootprint& footprint) const
        {
            DWORD index = 0;
            char subKeyName[256];
            DWORD subKeyNameSize = sizeof(subKeyName);

            while (RegEnumKeyExA(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
            {
                HKEY hSubKey;
                
                // Open the found folder
                if (RegOpenKeyExA(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                {
                    std::string fullPath = currentPath + "\\" + subKeyName;

                    // If there is a parameter "Id" inside the folder, it means this is the task itself
                    DWORD type = 0;
                    if (RegQueryValueExA(hSubKey, "Id", NULL, &type, NULL, NULL) == ERROR_SUCCESS)
                    {
                        // Using structure from Linux 
                        models::CronTask task;
                        task.filePath = "TaskCache\\Tree" + fullPath;
                        task.taskLine = "Windows Scheduled Task (Registry Persistence)";
                        footprint.scheduledTasks.push_back(std::move(task));
                    }

                    // Go deeper into the folder
                    enumTasks(hSubKey, fullPath, footprint);

                    // Close the opened subkey handle
                    RegCloseKey(hSubKey);
                }
                subKeyNameSize = sizeof(subKeyName);
                index++;
            }
        }
    };

    // Autopilot
    REGISTER_WINDOWS_ARTIFACT(ScheduledTaskScanner)
}
#endif