#include "ff/core/IArtifactSubScanner.h"
#include "ff/models/ForensicArtifacts.h"
#include "windows/WinRegistry.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <vector>
#include <string>
#include <cstdio>

namespace ff::windows
{
    class ArpScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            ULONG ulOutBufLen = sizeof(MIB_IPNETTABLE);
            std::vector<BYTE> buffer(ulOutBufLen);
            PMIB_IPNETTABLE pIpNetTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());

            if (GetIpNetTable(pIpNetTable, &ulOutBufLen, FALSE) == ERROR_INSUFFICIENT_BUFFER) 
            {
                buffer.resize(ulOutBufLen);
                pIpNetTable = reinterpret_cast<PMIB_IPNETTABLE>(buffer.data());
            }

            if (GetIpNetTable(pIpNetTable, &ulOutBufLen, FALSE) == NO_ERROR) 
            {
                for (DWORD i = 0; i < pIpNetTable->dwNumEntries; i++) 
                {
                    models::ArpTableEntry entry;
                    
                    IN_ADDR ipAddr;
                    ipAddr.S_un.S_addr = pIpNetTable->table[i].dwAddr;
                    char ipStr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ipAddr, ipStr, sizeof(ipStr));
                    entry.ipAddress = ipStr;

                    char macStr[18];
                    snprintf(macStr, sizeof(macStr), "%02X:%02X:%02X:%02X:%02X:%02X",
                        pIpNetTable->table[i].bPhysAddr[0], pIpNetTable->table[i].bPhysAddr[1],
                        pIpNetTable->table[i].bPhysAddr[2], pIpNetTable->table[i].bPhysAddr[3],
                        pIpNetTable->table[i].bPhysAddr[4], pIpNetTable->table[i].bPhysAddr[5]);
                    entry.macAddress = macStr;

                    switch (pIpNetTable->table[i].dwType) 
                    {
                        case MIB_IPNET_TYPE_DYNAMIC: entry.type = "Dynamic"; break;
                        case MIB_IPNET_TYPE_STATIC:  entry.type = "Static";  break;
                        case MIB_IPNET_TYPE_INVALID: entry.type = "Invalid"; break;
                        default:                     entry.type = "Other";   break;
                    }

                    footprint.arpEntries.push_back(entry);
                }
            }
        }
    };

    REGISTER_WINDOWS_ARTIFACT(ArpScanner)
}