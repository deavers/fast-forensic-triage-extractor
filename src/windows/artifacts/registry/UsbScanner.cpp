#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>

namespace ff::windows
{
    class UsbScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            HKEY hUsbStorKey;

            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hUsbStorKey) == ERROR_SUCCESS)
            {
                DWORD index = 0;
                char deviceName[256];
                DWORD deviceNameSize = sizeof(deviceName);

                while (RegEnumKeyExA(hUsbStorKey, index, deviceName, &deviceNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                {
                    HKEY hDeviceKey;

                    if (RegOpenKeyExA(hUsbStorKey, deviceName, 0, KEY_READ, &hDeviceKey) == ERROR_SUCCESS)
                    {
                        DWORD subIndex = 0;
                        char serialNumber[256];
                        DWORD serialNumberSize = sizeof(serialNumber);

                        if (RegEnumKeyExA(hDeviceKey, subIndex, serialNumber, &serialNumberSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                        {
                            HKEY hSerialKey;
                            
                            if (RegOpenKeyExA(hDeviceKey, serialNumber, 0, KEY_READ, &hSerialKey) == ERROR_SUCCESS)
                            {
                                char friendlyNameBuf[256] = "Unknown USB Device";
                                DWORD friendlyNameSize = sizeof(friendlyNameBuf);
                                RegQueryValueExA(hSerialKey, "FriendlyName", NULL, NULL, reinterpret_cast<LPBYTE>(friendlyNameBuf), &friendlyNameSize);

                                models::UsbHistoryEntry usb;
                                usb.deviceInstanceId = serialNumber;
                                usb.friendlyName = friendlyNameBuf;
                                footprint.usbHistory.push_back(std::move(usb));

                                RegCloseKey(hSerialKey);
                            }
                        }
                        RegCloseKey(hDeviceKey);
                    }
                    deviceNameSize = sizeof(deviceName);
                    index++;
                }
                RegCloseKey(hUsbStorKey);
            }
        }
    };
    REGISTER_WINDOWS_ARTIFACT(UsbScanner)
}
#endif