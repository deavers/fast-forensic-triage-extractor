#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>

namespace ff::windows
{
    class PersistenceScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            scanRegistryRun(footprint, HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM_Run");
            scanRegistryRun(footprint, HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU_Run");
            scanBootExecute(footprint);
            scanStartupFolder(footprint);
        }

    private:
        // Parse standard Run keys in HKLM and HKCU
        void scanRegistryRun(models::DigitalFootprint& footprint, HKEY rootKey, const std::string& path, const std::string& trigger) const
        {
            HKEY hKey;

            if (RegOpenKeyExA(rootKey, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                DWORD index = 0;
                char valueName[MAX_PATH];
                DWORD valueNameSize = sizeof(valueName);
                DWORD type = 0;
                BYTE data[MAX_PATH];
                DWORD dataSize = sizeof(data);

                // Parse all values in the registry branch
                while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL, &type, data, &dataSize) == ERROR_SUCCESS)
                {
                    if (type == REG_SZ || type == REG_EXPAND_SZ) // Only consider string values
                    {
                        models::PersistenceEntry entry;
                        entry.type = models::PersistenceType::RegistryRun;
                        entry.name = valueName;
                        entry.imagePath = reinterpret_cast<char*>(data);
                        entry.trigger = trigger;
                        footprint.persistence.push_back(std::move(entry));
                    }

                    valueNameSize = sizeof(valueName);
                    dataSize = sizeof(data);
                    index++;
                }
                RegCloseKey(hKey);
            }
        }

        // Parse the complex MULTI_SZ type for system-level auto-startup entries
        void scanBootExecute(models::DigitalFootprint& footprint) const
        {
            HKEY hKey;

            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                DWORD type = 0;
                DWORD dataSize = 0;
                
                // First query to get the required buffer size for BootExecute value
                if (RegQueryValueExA(hKey, "BootExecute", NULL, &type, NULL, &dataSize) == ERROR_SUCCESS)
                {
                    if (type == REG_MULTI_SZ)
                    {
                        std::vector<char> buffer(dataSize);
                        if (RegQueryValueExA(hKey, "BootExecute", NULL, NULL, reinterpret_cast<LPBYTE>(buffer.data()), &dataSize) == ERROR_SUCCESS)
                        {
                            // Parse strings separated by null bytes \0
                            const char* str = buffer.data();
                            while (*str)
                            {
                                models::PersistenceEntry entry;
                                entry.type = models::PersistenceType::RegistryRun;
                                entry.name = "BootExecute (Native)";
                                entry.imagePath = str;
                                entry.trigger = "Session Manager Pre-Boot";
                                footprint.persistence.push_back(std::move(entry));
                                
                                str += strlen(str) + 1; // Move to the next string
                            }
                        }
                    }
                }
                RegCloseKey(hKey);
            }
        }

        // Search for "shortcuts" in the Startup folder
        void scanStartupFolder(models::DigitalFootprint& footprint) const
        {
            char path[MAX_PATH];

            if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_STARTUP, NULL, 0, path)))
            {
                std::string searchPath = std::string(path) + "\\*";
                WIN32_FIND_DATAA findData;
                HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

                if (hFind != INVALID_HANDLE_VALUE)
                {
                    do 
                    {
                        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                        {
                            models::PersistenceEntry entry;
                            entry.type = models::PersistenceType::RegistryRun;
                            entry.name = findData.cFileName;
                            entry.imagePath = std::string(path) + "\\" + findData.cFileName;
                            entry.trigger = "Startup Folder LNK";
                            footprint.persistence.push_back(std::move(entry));
                        }
                    } while (FindNextFileA(hFind, &findData));
                    FindClose(hFind);
                }
            }
        }
    };

    REGISTER_WINDOWS_ARTIFACT(PersistenceScanner)
}
#endif