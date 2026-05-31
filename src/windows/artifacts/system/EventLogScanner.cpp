#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <winevt.h>
#include <string>

namespace ff::windows
{
    class EventLogScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // Search for failed logon events (Event ID 4625) in the Security event log
            // which indicates brute-force attempts or unauthorized access
            LPCWSTR query = L"*[System[(EventID=4625)]]";
            EVT_HANDLE hResults = EvtQuery(NULL, L"Security", query, EvtQueryChannelPath | EvtQueryReverseDirection);
            if (!hResults) 
                return; 

            EVT_HANDLE hEvent = NULL;
            DWORD dwReturned = 0;
            int count = 0;

            while (EvtNext(hResults, 1, &hEvent, INFINITE, 0, &dwReturned) && count < 5)
            {
                DWORD bufferSize = 0;
                DWORD propertyCount = 0;
                
                EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, NULL, &bufferSize, &propertyCount);
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
                {
                    LPWSTR buffer = (LPWSTR)malloc(bufferSize);
                    if (buffer)
                    {
                        EvtRender(NULL, hEvent, EvtRenderEventXml, bufferSize, buffer, &bufferSize, &propertyCount);
                        
                        int size_needed = WideCharToMultiByte(CP_UTF8, 0, buffer, -1, NULL, 0, NULL, NULL);
                        std::string xmlStr(size_needed - 1, 0);
                        WideCharToMultiByte(CP_UTF8, 0, buffer, -1, &xmlStr[0], size_needed, NULL, NULL);

                        models::EventLogEntry entry;
                        entry.eventId = "4625 (Failed Logon / Brute-Force)";
                        
                        size_t timePos = xmlStr.find("SystemTime='");
                        if (timePos != std::string::npos) 
                            entry.timestamp = xmlStr.substr(timePos + 12, 19); 
                        else 
                            entry.timestamp = "Unknown";

                        size_t userPos = xmlStr.find("TargetUserName'>");
                        if (userPos != std::string::npos) 
                        {
                            size_t endPos = xmlStr.find('<', userPos);
                            entry.details = "Target User: " + xmlStr.substr(userPos + 16, endPos - (userPos + 16));
                        } 
                        else 
                        {
                            entry.details = "Target User: Unknown";
                        }

                        footprint.eventLogs.push_back(std::move(entry));
                        free(buffer);
                    }
                }
                EvtClose(hEvent);
                count++;
            }
            EvtClose(hResults);
        }
    };

    REGISTER_WINDOWS_ARTIFACT(EventLogScanner)
}
#endif