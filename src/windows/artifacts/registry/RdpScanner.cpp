#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>

namespace ff::windows
{
    class RdpScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            HKEY hKey;
            // RDP connections path
            LPCWSTR rdpPath = L"Software\\Microsoft\\Terminal Server Client\\Servers";
            
            if (RegOpenKeyExW(HKEY_CURRENT_USER, rdpPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                DWORD index = 0;
                WCHAR subKeyName[256];
                DWORD subKeyNameSize = sizeof(subKeyName) / sizeof(WCHAR);

                // Enumerate all saved IP addresses/Hosts
                while (RegEnumKeyExW(hKey, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                {
                    models::RdpSession session;
                    
                    // Convert WCHAR to std::string
                    int size_needed = WideCharToMultiByte(CP_UTF8, 0, subKeyName, -1, NULL, 0, NULL, NULL);
                    std::string hostStr(size_needed - 1, 0);

                    WideCharToMultiByte(CP_UTF8, 0, subKeyName, -1, &hostStr[0], size_needed, NULL, NULL);
                    session.targetHost = hostStr;

                    // Try to read UsernameHint (under what username did you log in)
                    HKEY hSubKey;
                    if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                    {
                        WCHAR userHint[256];
                        DWORD hintSize = sizeof(userHint);

                        if (RegQueryValueExW(hSubKey, L"UsernameHint", NULL, NULL, (LPBYTE)userHint, &hintSize) == ERROR_SUCCESS)
                        {
                            int hint_size_needed = WideCharToMultiByte(CP_UTF8, 0, userHint, -1, NULL, 0, NULL, NULL);
                            std::string hintStr(hint_size_needed - 1, 0);

                            WideCharToMultiByte(CP_UTF8, 0, userHint, -1, &hintStr[0], hint_size_needed, NULL, NULL);
                            session.usernameHint = hintStr;
                        }
                        RegCloseKey(hSubKey);
                    }

                    if (session.usernameHint.empty()) 
                        session.usernameHint = "Unknown";
                    
                    footprint.rdpSessions.push_back(std::move(session));
                    
                    index++;
                    subKeyNameSize = sizeof(subKeyName) / sizeof(WCHAR);
                }
                RegCloseKey(hKey);
            }
        }
    };

    REGISTER_WINDOWS_ARTIFACT(RdpScanner)
}
#endif