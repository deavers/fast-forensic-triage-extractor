#include "LinuxSystemScanner.h"

#ifdef FF_PLATFORM_LINUX
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <unistd.h> // Needed for syscalls/permissions checking
#include <netinet/in.h> // ntohs for port conversion
#include <arpa/inet.h> // inet_ntop for IP conversion

namespace ff::linux_os
{
    std::string parseLinuxIp6(const std::string& hexStr)
    {
        if (hexStr.length() < 32) return "::";

        struct in6_addr addr6;
        uint32_t* p = reinterpret_cast<uint32_t*>(&addr6);

        // Linux kernel logs IPv6 in 4-byte parts in Little Endian format
        for (int i = 0; i < 4; ++i)
        {
            std::string part = hexStr.substr(i * 8, 8);
            p[i] = std::stoul(part, nullptr, 16);
        }

        char ipStr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, &addr6, ipStr, sizeof(ipStr)))
        {
            return std::string(ipStr);
        }
        return "::";
    }

    LinuxSystemScanner::LinuxSystemScanner(core::ScanMode mode) 
        : m_mode(mode) {}

    std::string_view LinuxSystemScanner::platformName() const
    {
        return ff::kPlatformName; 
    }

    std::vector<models::ProcessInfo> LinuxSystemScanner::scanProcesses()
    {
        std::vector<models::ProcessInfo> processes;

        if (!std::filesystem::exists("/proc")) {
            return processes;
        }

        // Iterate through the whole /proc directory
        for (const auto& entry : std::filesystem::directory_iterator("/proc"))
        {
            if (entry.is_directory())
            {
                std::string folderName = entry.path().filename().string();

                // If the folder name is numeric, it is a process
                if (std::all_of(folderName.begin(), folderName.end(), ::isdigit))
                {
                    uint32_t pid = std::stoul(folderName);
                    
                    // Read actual process status
                    auto procOpt = readProcStatus(pid);
                    if (procOpt)
                    {
                        processes.push_back(std::move(*procOpt)); // Move semantics
                    }
                }
            }
        }

        return processes;
    }

    std::optional<models::ProcessInfo> LinuxSystemScanner::readProcStatus(uint32_t pid) const
    {
        models::ProcessInfo proc;
        proc.pid = pid;
        proc.ppid = 0;
        proc.name = "Unknown_Linux_Proc";
        proc.memoryKB = 0;
        proc.isElevated = false;
        proc.isSignatureValid = false; // ELF signature checking is different in Linux

        std::string procFolder = "/proc/" + std::to_string(pid);
        
        // 1. Try reading the text status file
        std::ifstream statusFile(procFolder + "/status");
        if (!statusFile.is_open())
        {
            // If we cannot open the process file, we lack permissions (Access Denied)
            proc.exePath = std::nullopt;
            return proc;
        }

        std::string line;
        while (std::getline(statusFile, line))
        {
            // Look for process name
            if (line.rfind("Name:", 0) == 0)
            {
                proc.name = line.substr(5);
                // Clean up extra spaces and tabs
                proc.name.erase(0, proc.name.find_first_not_of(" \t"));
            }
            // Look for parent PID
            else if (line.rfind("PPid:", 0) == 0)
            {
                std::string ppidStr = line.substr(5);
                proc.ppid = std::stoul(ppidStr);
            }
        }
        statusFile.close();

        // 2. Read symlink to executable (exe Path)
        std::error_code ec;
        auto exeLink = std::filesystem::read_symlink(procFolder + "/exe", ec);
        if (!ec)
        {
            proc.exePath = exeLink.string();
        }
        else
        {
            proc.exePath = std::nullopt; // Access Denied for kernel system processes
        }

        return proc;
    }

    std::vector<models::NetworkConn> LinuxSystemScanner::scanNetwork()
    {
        std::vector<models::NetworkConn> connections;

        // Array of files to scan: IPv4 and IPv6
        std::vector<std::pair<std::string, bool>> netFiles = {
            {"/proc/net/tcp", false},
            {"/proc/net/tcp6", true}
        };

        for (const auto& [filePath, isIp6] : netFiles)
        {
            std::ifstream netFile(filePath);
            if (!netFile.is_open()) continue;

            std::string line;
            std::getline(netFile, line); // Skip header

            while (std::getline(netFile, line))
            {
                std::stringstream ss(line);
                std::string sl, local, remote, stateHex, tx_rx, tr_tm, retr, uidStr;
                ss >> sl >> local >> remote >> stateHex >> tx_rx >> tr_tm >> retr >> uidStr;

                if (local.empty() || remote.empty()) continue;

                models::NetworkConn conn;
                conn.protocol = models::Protocol::TCP;
                conn.uid = std::stoul(uidStr);

                // Parse local address
                auto localColon = local.find(':');
                if (localColon != std::string::npos)
                {
                    std::string ipHex = local.substr(0, localColon);
                    std::string portHex = local.substr(localColon + 1);
                    conn.localPort = static_cast<uint16_t>(std::stoul(portHex, nullptr, 16));

                    if (isIp6) {
                        conn.localAddr = parseLinuxIp6(ipHex); // Use our helper
                    } else {
                        struct in_addr addr;
                        addr.s_addr = std::stoul(ipHex, nullptr, 16);
                        char ipStr[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr))) conn.localAddr = ipStr;
                    }
                }

                // Parse remote address
                auto remoteColon = remote.find(':');
                if (remoteColon != std::string::npos)
                {
                    std::string ipHex = remote.substr(0, remoteColon);
                    std::string portHex = remote.substr(remoteColon + 1);
                    conn.remotePort = static_cast<uint16_t>(std::stoul(portHex, nullptr, 16));

                    if (isIp6) {
                        conn.remoteAddr = parseLinuxIp6(ipHex);
                    } else {
                        struct in_addr addr;
                        addr.s_addr = std::stoul(ipHex, nullptr, 16);
                        char ipStr[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr))) conn.remoteAddr = ipStr;
                    }
                }

                uint32_t stateVal = std::stoul(stateHex, nullptr, 16);
                switch (stateVal)
                {
                    case 0x01: conn.state = models::State::Established; break;
                    case 0x0A: conn.state = models::State::Listen; break;
                    case 0x06: conn.state = models::State::TimeWait; break;
                    case 0x04: conn.state = models::State::CloseWait; break;
                    default:   conn.state = models::State::Unknown; break;
                }

                conn.ownerPid = std::nullopt;
                connections.push_back(std::move(conn));
            }
            netFile.close();
        }

        return connections;
    }

    std::vector<models::PersistenceEntry> LinuxSystemScanner::scanPersistence()
    {
        return {}; 
    }

    std::vector<models::ServiceInfo> LinuxSystemScanner::scanServices()
    {
        return {};
    }

    models::DigitalFootprint LinuxSystemScanner::scanDigitalFootprint()
    {
        models::DigitalFootprint footprint;
        
        // Basic simulation for Linux so report is not empty
        footprint.anonymity.isProxyActive = false;
        footprint.anonymity.isVpnActive = false;
        footprint.anonymity.activeAdapters = "None";
        
        footprint.location.latitude = 49.8308;
        footprint.location.longitude = 18.1625;
        footprint.location.source = "Linux Geolocation Triage Simulator";
        
        return footprint;
    }

} // namespace ff::linux_os
#endif // FF_PLATFORM_LINUX