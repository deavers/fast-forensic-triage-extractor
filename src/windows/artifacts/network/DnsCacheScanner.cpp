#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>
#include <vector>
#include <sstream>

namespace ff::windows
{
    class DnsCacheScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // Create anonymous pipes for capturing console output
            HANDLE hReadPipe, hWritePipe;
            SECURITY_ATTRIBUTES saAttr;
            saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
            saAttr.bInheritHandle = TRUE; // Allow inheritance (needed for the child process to write to the pipe)
            saAttr.lpSecurityDescriptor = NULL;

            if (!CreatePipe(&hReadPipe, &hWritePipe, &saAttr, 0)) 
                return;
            SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0); // Reading end does not inherit

            // Configure hidden process execution
            STARTUPINFOA siStartInfo;
            ZeroMemory(&siStartInfo, sizeof(STARTUPINFOA));
            siStartInfo.cb = sizeof(STARTUPINFOA);
            siStartInfo.hStdError = hWritePipe;
            siStartInfo.hStdOutput = hWritePipe;
            siStartInfo.dwFlags |= STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            siStartInfo.wShowWindow = SW_HIDE; // Hide the console window

            PROCESS_INFORMATION piProcInfo;
            ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

            // System utility for dumping DNS cache
            char cmd[] = "ipconfig.exe /displaydns";

            if (CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &siStartInfo, &piProcInfo))
            {
                // Close the write end in our process (only needed for the child)
                CloseHandle(hWritePipe);

                // Read the output of the command into a string
                DWORD bytesRead;
                char buffer[4096];
                std::string output;

                while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0)
                {
                    buffer[bytesRead] = '\0';
                    output += buffer;
                }

                // Wait for the process to complete and close the handles
                WaitForSingleObject(piProcInfo.hProcess, 5000);
                CloseHandle(piProcInfo.hProcess);
                CloseHandle(piProcInfo.hThread);

                // Parse the output and populate the footprint
                parseDnsOutput(output, footprint);
            }
            else
            {
                CloseHandle(hWritePipe);
            }
            CloseHandle(hReadPipe);
        }

    private:
        void parseDnsOutput(const std::string& output, models::DigitalFootprint& footprint) const
        {
            std::istringstream stream(output);
            std::string line;
            std::string currentRecordName;

            while (std::getline(stream, line))
            {
                // Trim whitespace from the line
                line.erase(0, line.find_first_not_of(" \t\r\n"));
                line.erase(line.find_last_not_of(" \t\r\n") + 1);

                if (line.empty() || line.find("Windows IP Configuration") != std::string::npos) 
                    continue;

                if (line.find("Record Name") != std::string::npos)
                {
                    size_t colon = line.find(':');
                    if (colon != std::string::npos) 
                    {
                        currentRecordName = line.substr(colon + 2);
                    }
                }
                // Looking for A (Host) and CNAME records in the output
                else if (line.find("A (Host) Record") != std::string::npos || line.find("CNAME Record") != std::string::npos)
                {
                    size_t colon = line.find(':');
                    if (colon != std::string::npos) 
                    {
                        models::DnsCacheEntry entry;
                        entry.recordName = currentRecordName;
                        entry.recordType = (line.find("CNAME") != std::string::npos) ? "CNAME" : "A (IPv4)";
                        entry.data = line.substr(colon + 2);
                        footprint.dnsCache.push_back(std::move(entry));
                    }
                }
            }
        }
    };

    REGISTER_WINDOWS_ARTIFACT(DnsCacheScanner)
}
#endif