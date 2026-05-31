#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>

namespace ff::windows
{
    class BluetoothScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            HKEY hBthKey;

            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices", 0, KEY_READ, &hBthKey) == ERROR_SUCCESS)
            {
                DWORD index = 0;
                char macKeyName[256];
                DWORD macKeyNameSize = sizeof(macKeyName);

                while (RegEnumKeyExA(hBthKey, index, macKeyName, &macKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                {
                    HKEY hDeviceSubKey;
                    
                    if (RegOpenKeyExA(hBthKey, macKeyName, 0, KEY_READ, &hDeviceSubKey) == ERROR_SUCCESS)
                    {
                        char bthNameBuf[256] = "Unknown Bluetooth Device";
                        DWORD bthNameSize = sizeof(bthNameBuf);
                        
                        RegQueryValueExA(hDeviceSubKey, "Name", NULL, NULL, reinterpret_cast<LPBYTE>(bthNameBuf), &bthNameSize);

                        models::BluetoothDeviceEntry bth;
                        bth.macAddress = macKeyName;
                        bth.name = bthNameBuf;
                        footprint.bluetoothHistory.push_back(std::move(bth));

                        RegCloseKey(hDeviceSubKey);
                    }
                    macKeyNameSize = sizeof(macKeyName);
                    index++;
                }
                RegCloseKey(hBthKey);
            }
        }
    };
    REGISTER_WINDOWS_ARTIFACT(BluetoothScanner)
}
#endif