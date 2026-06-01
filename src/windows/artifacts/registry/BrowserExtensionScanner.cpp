#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>

namespace ff::windows
{
    class BrowserExtensionScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // CHROME
            scanBrowserRegistry(footprint, HKEY_CURRENT_USER, "Software\\Google\\Chrome\\Extensions", "Google Chrome (HKCU)");
            scanBrowserRegistry(footprint, HKEY_LOCAL_MACHINE, "Software\\Google\\Chrome\\Extensions", "Google Chrome (HKLM)");

            // EDGE
            scanBrowserRegistry(footprint, HKEY_CURRENT_USER, "Software\\Microsoft\\Edge\\Extensions", "Microsoft Edge (HKCU)");
            scanBrowserRegistry(footprint, HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Edge\\Extensions", "Microsoft Edge (HKLM)");
        }

    private:
        void scanBrowserRegistry(models::DigitalFootprint& footprint, HKEY rootKey, const std::string& path, const std::string& browserName) const
        {
            HKEY hKey;

            if (RegOpenKeyExA(rootKey, path.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                DWORD index = 0;
                char extId[256];
                DWORD extIdSize = sizeof(extId);

                // Enumerate all subkeys, each representing an installed extension
                while (RegEnumKeyExA(hKey, index, extId, &extIdSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                {
                    HKEY hSubKey;
                    
                    // Open the subkey for the extension to read its details
                    if (RegOpenKeyExA(hKey, extId, 0, KEY_READ, &hSubKey) == ERROR_SUCCESS)
                    {
                        char updateUrlBuf[512] = "Unknown Update URL (Possible Local Payload)";
                        DWORD updateUrlSize = sizeof(updateUrlBuf);
                        
                        // Try to read the update URL (legitimate extensions are updated from Google/Microsoft servers)
                        RegQueryValueExA(hSubKey, "update_url", NULL, NULL, reinterpret_cast<LPBYTE>(updateUrlBuf), &updateUrlSize);

                        models::BrowserExtensionEntry ext;
                        ext.browser = browserName;
                        ext.extensionId = extId;
                        ext.updateUrl = updateUrlBuf;
                        
                        footprint.browserExtensions.push_back(std::move(ext));

                        RegCloseKey(hSubKey);
                    }
                    extIdSize = sizeof(extId);
                    index++;
                }
                RegCloseKey(hKey);
            }
        }
    };

    // Autopilot
    REGISTER_WINDOWS_ARTIFACT(BrowserExtensionScanner)
}
#endif