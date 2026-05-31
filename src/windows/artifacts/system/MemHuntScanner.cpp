#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>

namespace ff::windows
{
    class MemHuntScanner : public core::IArtifactSubScanner
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
                    // Passing PID 0 (System Idle Process) causes access denied
                    if (pe32.th32ProcessID == 0) 
                        continue;

                    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                    if (hProcess)
                    {
                        MEMORY_BASIC_INFORMATION mbi;
                        LPBYTE addr = 0; 
                        
                        // Going through virtual memory of the process to find suspicious regions that are committed (potential code injection)
                        while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)))
                        {
                            // Fing memory that is: Committed, Private and has Read-Write-Execute (RWX) permissions
                            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE && 
                                (mbi.Protect == PAGE_EXECUTE_READWRITE || mbi.Protect == PAGE_EXECUTE_READ))
                            {
                                char mappedFileName[MAX_PATH];
                                
                                // If this memory is NOT mapped to a legitimate file (.dll or .exe) on the disk - this is injection!
                                if (GetMappedFileNameA(hProcess, addr, mappedFileName, MAX_PATH) == 0)
                                {
                                    models::InjectedMemoryEntry alert;
                                    alert.pid = std::to_string(pe32.th32ProcessID);
                                    alert.processName = pe32.szExeFile;
                                    
                                    char addrBuf[64];
                                    snprintf(addrBuf, sizeof(addrBuf), "0x%p", mbi.BaseAddress);
                                    alert.memoryAddress = addrBuf;
                                    
                                    alert.protection = (mbi.Protect == PAGE_EXECUTE_READWRITE) ? "RWX (High Risk)" : "RX (Suspicious)";
                                    
                                    footprint.injectedMemory.push_back(std::move(alert));
                                    break; // Found one anomaly, move to the next process
                                }
                            }
                            addr += mbi.RegionSize;
                        }
                        CloseHandle(hProcess);
                    }
                } while (Process32Next(hProcessSnap, &pe32));
            }
            CloseHandle(hProcessSnap);
        }
    };

    REGISTER_WINDOWS_ARTIFACT(MemHuntScanner)
}
#endif