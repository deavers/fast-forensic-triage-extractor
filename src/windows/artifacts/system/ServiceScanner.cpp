#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <winsvc.h>
#include <string>

namespace ff::windows
{
    class ServiceScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            SC_HANDLE hSCManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
            if (!hSCManager) 
                return;

            DWORD bytesNeeded = 0;
            DWORD servicesReturned = 0;
            DWORD resumeHandle = 0;

            // Getting the required buffer size for service enumeration
            EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                  NULL, 0, &bytesNeeded, &servicesReturned, &resumeHandle, NULL);

            if (GetLastError() == ERROR_MORE_DATA)
            {
                std::vector<BYTE> buffer(bytesNeeded);
                ENUM_SERVICE_STATUS_PROCESSA* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.data());

                if (EnumServicesStatusExA(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                                          reinterpret_cast<LPBYTE>(services), bytesNeeded, 
                                          &bytesNeeded, &servicesReturned, &resumeHandle, NULL))
                {
                    for (DWORD i = 0; i < servicesReturned; i++)
                    {
                        models::ServiceInfo sInfo;
                        sInfo.name = services[i].lpServiceName;
                        sInfo.displayName = services[i].lpDisplayName;
                        
                        // Determining the startup type
                        if (services[i].ServiceStatusProcess.dwCurrentState == SERVICE_RUNNING) 
                            sInfo.startType = "Running";
                        else if (services[i].ServiceStatusProcess.dwCurrentState == SERVICE_STOPPED) 
                            sInfo.startType = "Stopped";
                        else 
                            sInfo.startType = "Other (" + std::to_string(services[i].ServiceStatusProcess.dwCurrentState) + ")";

                        sInfo.serviceType = (services[i].ServiceStatusProcess.dwServiceType & SERVICE_WIN32_OWN_PROCESS) ? "Win32 Own Process" : "Win32 Shared Process";
                        
                        // For getting exact path exe service, we read the registry
                        std::string regPath = "SYSTEM\\CurrentControlSet\\Services\\" + sInfo.name;
                        HKEY hKey;
                        sInfo.imagePath = "Unknown Path";
                        
                        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) 
                        {
                            char pathBuf[MAX_PATH];
                            DWORD pathSize = sizeof(pathBuf);
                            if (RegQueryValueExA(hKey, "ImagePath", NULL, NULL, reinterpret_cast<LPBYTE>(pathBuf), &pathSize) == ERROR_SUCCESS) 
                            {
                                sInfo.imagePath = pathBuf;
                            }
                            RegCloseKey(hKey);
                        }

                        footprint.services.push_back(std::move(sInfo));
                    }
                }
            }
            CloseServiceHandle(hSCManager);
        }
    };

    REGISTER_WINDOWS_ARTIFACT(ServiceScanner)
}
#endif