#include "ff/core/IArtifactSubScanner.h"
#include "ff/models/ForensicArtifacts.h"
#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace ff::windows
{
    class UserActivityScanner : public core::IArtifactSubScanner
    {
    private:
        std::string WideToUtf8(const std::wstring& wstr) const 
        {
            if (wstr.empty()) 
                return "";

            int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
            std::string strTo(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
            
            return strTo;
        }

        std::string DecodeROT13AndConvert(const std::wstring& wInput) const 
        {
            std::wstring result = wInput;

            for (wchar_t& wc : result) 
            {
                if ((wc >= L'a' && wc <= L'm') || (wc >= L'A' && wc <= L'M')) 
                    wc += 13;

                else if ((wc >= L'n' && wc <= L'z') || (wc >= L'N' && wc <= L'Z')) 
                    wc -= 13;
            }
            return WideToUtf8(result);
        }

        void ScanUserAssist(HKEY hKeyRoot, const std::wstring& guid, models::DigitalFootprint& footprint) const 
        {
            std::wstring fullPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\" + guid + L"\\Count";
            HKEY hKey;
            
            if (RegOpenKeyExW(hKeyRoot, fullPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) 
            {
                DWORD index = 0;
                wchar_t valueName[2048];
                DWORD valueNameLen = 2048;
                DWORD type = 0;
                BYTE data[1024];
                DWORD dataLen = sizeof(data);

                while (RegEnumValueW(hKey, index, valueName, &valueNameLen, nullptr, &type, data, &dataLen) == ERROR_SUCCESS) 
                {
                    if (type == REG_BINARY && dataLen >= 8) 
                    {
                        std::wstring wName(valueName, valueNameLen); 

                        if (wName != L"Version") 
                        {
                            std::string decodedPath = DecodeROT13AndConvert(wName);
                            uint32_t runCount = *reinterpret_cast<uint32_t*>(data + 4);
                            uint32_t focusTimeMs = (dataLen >= 16) ? *reinterpret_cast<uint32_t*>(data + 12) : 0;
                            
                            // Add the artifact regardless of runCount (Windows 11 quirk)
                            models::UserActivityEntry entry;
                            entry.programPath = "[UserAssist] " + decodedPath;
                            entry.runCount = runCount;
                            entry.totalActiveMinutes = focusTimeMs / 60000;
                            footprint.userActivity.push_back(entry);
                        }
                    }

                    index++;
                    valueNameLen = 2048;
                    dataLen = sizeof(data);
                }
                RegCloseKey(hKey);
            }
        }

        void ScanRunMRU(HKEY hKeyRoot, models::DigitalFootprint& footprint) const 
        {
            HKEY hKey;

            if (RegOpenKeyExW(hKeyRoot, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", 0, KEY_READ, &hKey) == ERROR_SUCCESS) 
            {
                DWORD index = 0;
                wchar_t valueName[256];
                DWORD valueNameLen = 256;
                DWORD type = 0;
                wchar_t data[2048];
                DWORD dataLen = sizeof(data);

                while (RegEnumValueW(hKey, index, valueName, &valueNameLen, nullptr, &type, reinterpret_cast<BYTE*>(data), &dataLen) == ERROR_SUCCESS) 
                {
                    std::wstring wName(valueName, valueNameLen);

                    if (type == REG_SZ && wName != L"MRUList") 
                    {
                        std::wstring wData(data, dataLen / sizeof(wchar_t));
                        if (!wData.empty() && wData.back() == L'\0') 
                            wData.pop_back();

                        models::UserActivityEntry entry;
                        entry.programPath = "[Win+R Command] " + WideToUtf8(wData);
                        entry.runCount = 1; 
                        entry.totalActiveMinutes = 0;
                        footprint.userActivity.push_back(entry);
                    }

                    index++;
                    valueNameLen = 256;
                    dataLen = sizeof(data);
                }
                RegCloseKey(hKey);
            }
        }

    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // Classic UserAssist (Windows 7-8.1)
            ScanUserAssist(HKEY_CURRENT_USER, L"{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}", footprint);
            
            // Inkey UserAssist (Windows 10/11)
            ScanUserAssist(HKEY_CURRENT_USER, L"{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}", footprint);

            // UWP UserAssist (Windows 10/11)
            ScanUserAssist(HKEY_CURRENT_USER, L"{6D809377-6AF0-444B-8957-A3773F02200E}", footprint);

            // Fallback History of "Run" dialog (Win+R)
            ScanRunMRU(HKEY_CURRENT_USER, footprint);

            // Diagnostic entry if no activity found (common on Windows 11 with disabled tracking)
            if (footprint.userActivity.empty()) 
            {
                models::UserActivityEntry diagnostic;
                diagnostic.programPath = "[DIAGNOSTIC] OS tracking is disabled. No activity found in UserAssist or RunMRU.";
                diagnostic.runCount = 0;
                diagnostic.totalActiveMinutes = 0;
                footprint.userActivity.push_back(diagnostic);
            }
        }
    };

    REGISTER_WINDOWS_ARTIFACT(UserActivityScanner)
}