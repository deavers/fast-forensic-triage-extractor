#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <iphlpapi.h>
#include <string>
#include <vector>

namespace ff::windows
{
    class NetworkConnectionsScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            // Function 31: Collect TCP Connections (IPv4)
            ULONG size = 0;
            GetTcpTable(NULL, &size, TRUE);
            
            std::vector<BYTE> buffer(size);
            PMIB_TCPTABLE tcpTable = reinterpret_cast<PMIB_TCPTABLE>(buffer.data());

            if (GetTcpTable(tcpTable, &size, TRUE) == NO_ERROR)
            {
                for (DWORD i = 0; i < tcpTable->dwNumEntries; i++)
                {
                    models::NetworkConnEntry conn;
                    conn.protocol = "TCP";
                    
                    struct in_addr localAddr;
                    localAddr.s_addr = tcpTable->table[i].dwLocalAddr;
                    conn.localIp = inet_ntoa(localAddr);

                    conn.localPort = std::to_string(ntohs(static_cast<u_short>(tcpTable->table[i].dwLocalPort)));

                    struct in_addr remoteAddr;
                    remoteAddr.s_addr = tcpTable->table[i].dwRemoteAddr;
                    conn.remoteIp = inet_ntoa(remoteAddr);
                    conn.remotePort = std::to_string(ntohs(static_cast<u_short>(tcpTable->table[i].dwRemotePort)));

                    switch (tcpTable->table[i].dwState)
                    {
                        case MIB_TCP_STATE_ESTAB:   conn.state = "ESTABLISHED"; break;
                        case MIB_TCP_STATE_LISTEN:  conn.state = "LISTENING"; break;
                        case MIB_TCP_STATE_CLOSE_WAIT: conn.state = "CLOSE_WAIT"; break;
                        case MIB_TCP_STATE_TIME_WAIT:  conn.state = "TIME_WAIT"; break;
                        default: conn.state = "UNKNOWN (" + std::to_string(tcpTable->table[i].dwState) + ")"; break;
                    }

                    footprint.networkConnections.push_back(std::move(conn));
                }
            }

            // Function 32: Collect UDP Listening Ports
            size = 0;
            GetUdpTable(NULL, &size, TRUE);
            
            std::vector<BYTE> udpBuffer(size);
            PMIB_UDPTABLE udpTable = reinterpret_cast<PMIB_UDPTABLE>(udpBuffer.data());

            if (GetUdpTable(udpTable, &size, TRUE) == NO_ERROR)
            {
                for (DWORD i = 0; i < udpTable->dwNumEntries; i++)
                {
                    models::NetworkConnEntry conn;
                    conn.protocol = "UDP";
                    
                    struct in_addr localAddr;
                    localAddr.s_addr = udpTable->table[i].dwLocalAddr;
                    conn.localIp = inet_ntoa(localAddr);
                    conn.localPort = std::to_string(ntohs(static_cast<u_short>(udpTable->table[i].dwLocalPort)));
                    
                    conn.remoteIp = "0.0.0.0";
                    conn.remotePort = "*";
                    conn.state = "LISTENING";

                    footprint.networkConnections.push_back(std::move(conn));
                }
            }
        }
    };

    // Register the scanner for automatic discovery
    REGISTER_WINDOWS_ARTIFACT(NetworkConnectionsScanner)
}
#endif