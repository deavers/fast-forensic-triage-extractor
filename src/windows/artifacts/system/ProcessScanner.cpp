#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>

#include <cstring>

namespace ff::windows
{
    class ProcessScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hProcessSnap == INVALID_HANDLE_VALUE) 
                return;

            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);

            if (Process32First(hProcessSnap, &pe32))
            {
                do 
                {
                    if (pe32.th32ProcessID == 0) 
                        continue;

                    models::ProcessInfo pInfo;
                    pInfo.pid = pe32.th32ProcessID;
                    pInfo.ppid = pe32.th32ParentProcessID;
                    pInfo.name = pe32.szExeFile;
                    
                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                    if (hProcess)
                    {
                        // Getting path
                        char exePath[MAX_PATH];
                        if (GetModuleFileNameExA(hProcess, NULL, exePath, MAX_PATH)) 
                            pInfo.exePath = std::string(exePath);
                        
                        // Check if the process is elevated (running with admin privileges)
                        HANDLE hToken;
                        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) 
                        {
                            TOKEN_ELEVATION elevation;
                            DWORD cbSize = sizeof(TOKEN_ELEVATION);

                            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize))
                                pInfo.isElevated = elevation.TokenIsElevated;
                            
                            CloseHandle(hToken);
                        }

                        // Getting memory usage
                        PROCESS_MEMORY_COUNTERS pmc;
                        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
                            pInfo.memoryKB = pmc.WorkingSetSize / 1024;

                        // Check digital signature validity (Function 29)
                        if (pInfo.exePath)
                            pInfo.isSignatureValid = checkSignature(*pInfo.exePath);

                        CloseHandle(hProcess);
                    }
                    else 
                    {
                        pInfo.isElevated = false; 
                        pInfo.memoryKB = 0;
                        pInfo.isSignatureValid = false;
                    }

                    footprint.processes.push_back(std::move(pInfo));

                } while (Process32Next(hProcessSnap, &pe32));
            }
            CloseHandle(hProcessSnap);
        }

    private:
        bool checkSignature(const std::string& filePath) const
        {
            std::wstring wPath(filePath.begin(), filePath.end());
            
            WINTRUST_FILE_INFO fileData;
            memset(&fileData, 0, sizeof(WINTRUST_FILE_INFO));
            fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileData.pcwszFilePath = wPath.c_str();

            WINTRUST_DATA trustData;
            memset(&trustData, 0, sizeof(WINTRUST_DATA));
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.dwUIChoice = WTD_UI_NONE;
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileData;
            trustData.dwStateAction = WTD_STATEACTION_VERIFY;

            GUID actionGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            LONG status = WinVerifyTrust(NULL, &actionGuid, &trustData);

            trustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &actionGuid, &trustData);

            return (status == ERROR_SUCCESS);
        }
    };

    REGISTER_WINDOWS_ARTIFACT(ProcessScanner)
}
#endif