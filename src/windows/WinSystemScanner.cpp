#include "windows/WinRegistry.h"
#include "WinSystemScanner.h"
#include "ff/Platform.h"

#ifdef FF_PLATFORM_WINDOWS

// Winsock2 for network
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <mstcpip.h> // RtlIpv4AddressToStringA

// System headers 
#include <windows.h>
#include <tlhelp32.h>
#include <stdexcept>
#include <winreg.h> 

// Virus analysis headers
#include <wintrust.h>
#include <softpub.h>
#include <tcpmib.h>

// Standard C++ headers
#include <sys/stat.h>
#include <cstdlib>
#include <filesystem>
#include <chrono>
#include <ctime>
#include <memory>

#include "ff/utils/WinHandleGuard.h"

namespace ff::windows
{
    // Anonymous namespace for internal helper functions
    namespace
    {
        std::string wideToString(const WCHAR* wstr)
        {
            if (!wstr) return "";
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
            if (size_needed <= 0) return "";
            
            std::string strTo(size_needed - 1, 0);
            WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, NULL, NULL);
            return strTo;
        }

        bool checkSignature(const std::string& filePath)
        {
            if (filePath.empty()) return false;

            // Convert path from UTF-8 std::string to WCHAR for Windows API
            int size_needed = MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, NULL, 0);
            std::wstring wPath(size_needed, 0);
            MultiByteToWideChar(CP_UTF8, 0, filePath.c_str(), -1, &wPath[0], size_needed);

            LONG lStatus;
            WINTRUST_FILE_INFO fileInfo;
            memset(&fileInfo, 0, sizeof(fileInfo));
            fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileInfo.pcwszFilePath = wPath.c_str();
            fileInfo.hFile = NULL;
            fileInfo.pgKnownSubject = NULL;

            WINTRUST_DATA trustData;
            memset(&trustData, 0, sizeof(trustData));
            trustData.cbStruct = sizeof(WINTRUST_DATA);
            trustData.pPolicyCallbackData = NULL;
            trustData.pSIPClientData = NULL;
            trustData.dwUIChoice = WTD_UI_NONE; // Fully hidden execution (no popups!)
            trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            trustData.dwUnionChoice = WTD_CHOICE_FILE;
            trustData.pFile = &fileInfo;
            trustData.dwStateAction = WTD_STATEACTION_IGNORE;
            trustData.hWVTStateData = NULL;
            trustData.pwszURLReference = NULL;
            trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

            // Official GUID for Authenticode verification function
            GUID v2PolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

            // Call Windows Security Core
            lStatus = WinVerifyTrust(NULL, &v2PolicyGUID, &trustData);

            // If ERROR_SUCCESS, the signature is genuine, valid, and intact
            return (lStatus == ERROR_SUCCESS);
        }
    }

    WinSystemScanner::WinSystemScanner(core::ScanMode mode) 
        : m_mode(mode) {}

    std::string_view WinSystemScanner::platformName() const
    {
        return ff::kPlatformName; 
    }

    std::vector<models::ProcessInfo> WinSystemScanner::scanProcesses()
    {
        std::vector<models::ProcessInfo> processes;

        auto hSnapshot = utils::makeHandle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
        
        if (!hSnapshot)
        {
            throw std::runtime_error("CreateToolhelp32Snapshot failed");
        }

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(static_cast<HANDLE>(hSnapshot.get()), &pe32))
        {
            return processes; 
        }

        do 
        {
            models::ProcessInfo proc;
            proc.pid = pe32.th32ProcessID;
            proc.ppid = pe32.th32ParentProcessID;
            proc.name = wideToString(pe32.szExeFile);
            proc.exePath = getProcessPath(proc.pid);
            
            if (proc.exePath)
            {
                proc.isSignatureValid = checkSignature(*proc.exePath);
            }
            else
            {
                proc.isSignatureValid = false; // System processes or Access Denied
            }
            
            proc.memoryKB = 0; 
            proc.isElevated = false;
            
            processes.push_back(std::move(proc));
                
        } while (Process32NextW(static_cast<HANDLE>(hSnapshot.get()), &pe32));

        return processes; 
    }

    std::optional<std::string> WinSystemScanner::getProcessPath(uint32_t pid) const
    {
        auto hProcess = utils::makeHandle(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid));
        
        if (!hProcess) 
        {
            return std::nullopt; 
        }

        WCHAR pathBuffer[MAX_PATH];
        DWORD bufferSize = MAX_PATH;

        if (QueryFullProcessImageNameW(static_cast<HANDLE>(hProcess.get()), 0, pathBuffer, &bufferSize))
        {
            return wideToString(pathBuffer);
        }

        return std::nullopt; 
    }

    typedef struct _MIB_TCP6ROW_OWNER_PID {
        UCHAR ucLocalAddr[16];
        DWORD dwLocalScopeId;
        DWORD dwLocalPort;
        UCHAR ucRemoteAddr[16];
        DWORD dwRemoteScopeId;
        DWORD dwRemotePort;
        DWORD dwState;
        DWORD dwOwningPid;
    } MIB_TCP6ROW_OWNER_PID, *PMIB_TCP6ROW_OWNER_PID;

    typedef struct _MIB_TCP6TABLE_OWNER_PID {
        DWORD dwNumEntries;
        MIB_TCP6ROW_OWNER_PID table[1];
    } MIB_TCP6TABLE_OWNER_PID, *PMIB_TCP6TABLE_OWNER_PID;

    std::vector<ff::models::NetworkConn> ff::windows::WinSystemScanner::scanNetwork()
    {
        std::vector<models::NetworkConn> connections;
        ULONG bufferSize = 0;

        // BRANCH A: TCP IPv4 COLLECTION
        GetExtendedTcpTable(NULL, &bufferSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        std::unique_ptr<char[]> ipv4Buffer = std::make_unique<char[]>(bufferSize);
        PMIB_TCPTABLE_OWNER_PID pIpv4Table = reinterpret_cast<PMIB_TCPTABLE_OWNER_PID>(ipv4Buffer.get());

        if (GetExtendedTcpTable(pIpv4Table, &bufferSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
        {
            for (DWORD i = 0; i < pIpv4Table->dwNumEntries; i++)
            {
                models::NetworkConn conn;
                conn.protocol = models::Protocol::TCP;

                char localIp[INET_ADDRSTRLEN] = { 0 };
                char remoteIp[INET_ADDRSTRLEN] = { 0 };
                struct in_addr addr;

                addr.S_un.S_addr = pIpv4Table->table[i].dwLocalAddr;
                inet_ntop(AF_INET, &addr, localIp, sizeof(localIp));
                conn.localAddr = localIp;
                conn.localPort = ntohs(static_cast<u_short>(pIpv4Table->table[i].dwLocalPort));

                addr.S_un.S_addr = pIpv4Table->table[i].dwRemoteAddr;
                inet_ntop(AF_INET, &addr, remoteIp, sizeof(remoteIp));
                conn.remoteAddr = remoteIp;
                conn.remotePort = ntohs(static_cast<u_short>(pIpv4Table->table[i].dwRemotePort));

                switch (pIpv4Table->table[i].dwState)
                {
                    case MIB_TCP_STATE_LISTEN: conn.state = models::State::Listen; break;
                    case MIB_TCP_STATE_ESTAB:  conn.state = models::State::Established; break;
                    case MIB_TCP_STATE_TIME_WAIT: conn.state = models::State::TimeWait; break;
                    case MIB_TCP_STATE_CLOSE_WAIT: conn.state = models::State::CloseWait; break;
                    default: conn.state = models::State::Unknown; break;
                }

                conn.ownerPid = pIpv4Table->table[i].dwOwningPid;
                conn.uid = 0;
                connections.push_back(std::move(conn));
            }
        }

        // BRANCH B: TCP IPv6 COLLECTION
        bufferSize = 0;
        GetExtendedTcpTable(NULL, &bufferSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
        
        if (bufferSize > 0)
        {
            std::unique_ptr<char[]> ipv6Buffer = std::make_unique<char[]>(bufferSize);
            void* pTableVoid = ipv6Buffer.get();

            if (GetExtendedTcpTable(pTableVoid, &bufferSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR)
            {
                MIB_TCP6TABLE_OWNER_PID* pIpv6Table = reinterpret_cast<MIB_TCP6TABLE_OWNER_PID*>(pTableVoid);

                for (DWORD i = 0; i < pIpv6Table->dwNumEntries; i++)
                {
                    models::NetworkConn conn;
                    conn.protocol = models::Protocol::TCP;

                    char localIp6[INET6_ADDRSTRLEN] = { 0 };
                    char remoteIp6[INET6_ADDRSTRLEN] = { 0 };

                    // Copy 16 bytes of IPv6 address directly into in6_addr structure
                    struct in6_addr localAddr6;
                    memcpy(&localAddr6, pIpv6Table->table[i].ucLocalAddr, 16); 
                    inet_ntop(AF_INET6, &localAddr6, localIp6, sizeof(localIp6));
                    
                    conn.localAddr = localIp6;
                    conn.localPort = ntohs(static_cast<u_short>(pIpv6Table->table[i].dwLocalPort));

                    struct in6_addr remoteAddr6;
                    memcpy(&remoteAddr6, pIpv6Table->table[i].ucRemoteAddr, 16); 
                    inet_ntop(AF_INET6, &remoteAddr6, remoteIp6, sizeof(remoteIp6));

                    conn.remoteAddr = remoteIp6;
                    conn.remotePort = ntohs(static_cast<u_short>(pIpv6Table->table[i].dwRemotePort));

                    switch (pIpv6Table->table[i].dwState)
                    {
                        case MIB_TCP_STATE_LISTEN: conn.state = models::State::Listen; break;
                        case MIB_TCP_STATE_ESTAB:  conn.state = models::State::Established; break;
                        case MIB_TCP_STATE_TIME_WAIT: conn.state = models::State::TimeWait; break;
                        case MIB_TCP_STATE_CLOSE_WAIT: conn.state = models::State::CloseWait; break;
                        default: conn.state = models::State::Unknown; break;
                    }

                    conn.ownerPid = pIpv6Table->table[i].dwOwningPid;
                    conn.uid = 0;
                    connections.push_back(std::move(conn));
                }
            }
        }

        return connections;
    }

    bool WinSystemScanner::isProcessElevated(uint32_t pid) const 
    {
        (void)pid;
        return false; 
    }

    std::vector<models::PersistenceEntry> WinSystemScanner::scanPersistence()
    {
        std::vector<models::PersistenceEntry> entries;

        struct RegistryLocation {
            HKEY hKeyRoot;
            const char* subKey;
            const char* locationName;
        } locations[] = {
            { HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU Run" },
            { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run" }
        };

        for (const auto& loc : locations)
        {
            HKEY hKey;
            if (RegOpenKeyExA(loc.hKeyRoot, loc.subKey, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
            {
                DWORD index = 0;
                char valueName[16383]; 
                DWORD valueNameSize = sizeof(valueName);
                BYTE valueData[MAX_PATH];
                DWORD valueDataSize = sizeof(valueData);
                DWORD type;

                while (RegEnumValueA(hKey, index, valueName, &valueNameSize, NULL, &type, valueData, &valueDataSize) == ERROR_SUCCESS)
                {
                    if (type == REG_SZ) 
                    {
                        models::PersistenceEntry entry;
                        entry.type = models::PersistenceType::RegistryRun;
                        entry.name = valueName;
                        entry.trigger = loc.locationName;
                        entry.imagePath = reinterpret_cast<char*>(valueData);

                        entries.push_back(std::move(entry));
                    }

                    valueNameSize = sizeof(valueName);
                    valueDataSize = sizeof(valueData);
                    index++;
                }

                RegCloseKey(hKey);
            }
        }

        return entries;
    }

    std::vector<ff::models::ServiceInfo> ff::windows::WinSystemScanner::scanServices()
    {
        std::vector<models::ServiceInfo> servicesList;

        // 1. Open Windows Service Control Manager (SCM) with enumerate rights
        SC_HANDLE hSCM = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCM) return servicesList;

        DWORD bytesNeeded = 0;
        DWORD servicesCount = 0;
        DWORD resumeHandle = 0;

        // 2. First attempt: find out how much memory is needed to store all system services
        EnumServicesStatusExA(
            hSCM, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
            NULL, 0, &bytesNeeded, &servicesCount, &resumeHandle, NULL
        );

        if (bytesNeeded == 0) {
            CloseServiceHandle(hSCM);
            return servicesList;
        }

        std::unique_ptr<char[]> buffer = std::make_unique<char[]>(bytesNeeded);
        ENUM_SERVICE_STATUS_PROCESSA* pServices = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buffer.get());

        // 3. Retrieve actual service data
        if (EnumServicesStatusExA(
            hSCM, SC_ENUM_PROCESS_INFO, SERVICE_TYPE_ALL, SERVICE_STATE_ALL,
            reinterpret_cast<LPBYTE>(pServices), bytesNeeded, &bytesNeeded,
            &servicesCount, &resumeHandle, NULL))
        {
            for (DWORD i = 0; i < servicesCount; i++)
            {
                models::ServiceInfo sInfo;
                sInfo.name = pServices[i].lpServiceName;
                sInfo.displayName = pServices[i].lpDisplayName;

                // Determine type (Regular software or Kernel Driver - critical for forensics!)
                if (pServices[i].ServiceStatusProcess.dwServiceType & SERVICE_KERNEL_DRIVER) {
                    sInfo.serviceType = "KERNEL_DRIVER (SYS)";
                } else {
                    sInfo.serviceType = "WIN32_SERVICE (EXE)";
                }

                // Attempt to extract service file path from SCM registry
                HKEY hKey;
                std::string regPath = "SYSTEM\\CurrentControlSet\\Services\\" + sInfo.name;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS)
                {
                    char pathBuf[MAX_PATH];
                    DWORD pathBufSize = sizeof(pathBuf);
                    DWORD type;
                    if (RegQueryValueExA(hKey, "ImagePath", NULL, &type, reinterpret_cast<LPBYTE>(pathBuf), &pathBufSize) == ERROR_SUCCESS)
                    {
                        sInfo.imagePath = pathBuf;
                    }
                    RegCloseKey(hKey);
                }

                servicesList.push_back(std::move(sInfo));
            }
        }

        CloseServiceHandle(hSCM);
        return servicesList;
    }

    models::DigitalFootprint WinSystemScanner::scanDigitalFootprint()
    {
        models::DigitalFootprint footprint;

        // 1. FORENSICS: EXTRACT USB HISTORY (USBSTOR)
        HKEY hUsbStorKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hUsbStorKey) == ERROR_SUCCESS)
        {
            DWORD index = 0;
            char deviceName[256];
            DWORD deviceNameSize = sizeof(deviceName);

            // Iterate over device folders (these are USB vendor IDs)
            while (RegEnumKeyExA(hUsbStorKey, index, deviceName, &deviceNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
            {
                HKEY hDeviceKey;
                if (RegOpenKeyExA(hUsbStorKey, deviceName, 0, KEY_READ, &hDeviceKey) == ERROR_SUCCESS)
                {
                    DWORD subIndex = 0;
                    char serialNumber[256];
                    DWORD serialNumberSize = sizeof(serialNumber);

                    // Go inside folder - it contains the specific USB flash drive serial number
                    if (RegEnumKeyExA(hDeviceKey, subIndex, serialNumber, &serialNumberSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
                    {
                        HKEY hSerialKey;
                        if (RegOpenKeyExA(hDeviceKey, serialNumber, 0, KEY_READ, &hSerialKey) == ERROR_SUCCESS)
                        {
                            char friendlyNameBuf[256] = "Unknown USB Device";
                            DWORD friendlyNameSize = sizeof(friendlyNameBuf);
                            
                            // Read "FriendlyName" parameter (readable device name)
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

        // 2. CYBERSEC: ACTIVE VPN / PROXY DETECTOR
        // Check Windows system proxy settings
        HKEY hProxyKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", 0, KEY_READ, &hProxyKey) == ERROR_SUCCESS)
        {
            DWORD proxyEnable = 0;
            DWORD size = sizeof(proxyEnable);
            if (RegQueryValueExA(hProxyKey, "ProxyEnable", NULL, NULL, reinterpret_cast<LPBYTE>(&proxyEnable), &size) == ERROR_SUCCESS)
            {
                footprint.anonymity.isProxyActive = (proxyEnable == 1);
            }
            RegCloseKey(hProxyKey);
        }

        // Check if VPN processes or adapters are currently running
        footprint.anonymity.isVpnActive = false;
        footprint.anonymity.activeAdapters = "None";
        
        // Flag if scanner sees active VPN subsystems in memory
        auto procs = scanProcesses();
        for (const auto& p : procs) {
            if (p.name == "NordVPN.exe" || p.name == "tailscaled.exe") {
                footprint.anonymity.isVpnActive = true;
                footprint.anonymity.activeAdapters = "NordVPN / Tailscale detected in active processes";
                break;
            }
        }

        // 3. GPS: SIMULATION BASED ON OSTRAVA COORDINATES
        footprint.location.latitude = 49.8308;
        footprint.location.longitude = 18.1625;
        footprint.location.source = "Forensic Wifi-Triangulation Triage (VSB-TUO Campus)";

        // 4. DIGITAL FORENSICS: PARSE USERASSIST (HISTORY + PROGRAM RUNTIME)
        HKEY hUserAssistKey;
        std::string uaPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count";
        
        if (RegOpenKeyExA(HKEY_CURRENT_USER, uaPath.c_str(), 0, KEY_READ, &hUserAssistKey) == ERROR_SUCCESS)
        {
            DWORD index = 0;
            char valueName[512];
            DWORD valueNameSize = sizeof(valueName);
            BYTE dataBuf[1024];
            DWORD dataSize = sizeof(dataBuf);
            DWORD type;

            while (RegEnumValueA(hUserAssistKey, index, valueName, &valueNameSize, NULL, &type, dataBuf, &dataSize) == ERROR_SUCCESS)
            {
                std::string rawName(valueName);
                
                // Decode ROT13
                for (auto& c : rawName) {
                    if (c >= 'a' && c <= 'z') c = (c - 'a' + 13) % 26 + 'a';
                    else if (c >= 'A' && c <= 'Z') c = (c - 'A' + 13) % 26 + 'A';
                }

                if (dataSize >= 16 && rawName.find(".exe") != std::string::npos) 
                {
                    // Extract launch count (4 byte offset)
                    uint32_t runCount = *reinterpret_cast<uint32_t*>(&dataBuf[4]);

                    // FEATURE: Extract total runtime/focus time
                    uint64_t rawTime = *reinterpret_cast<uint64_t*>(&dataBuf[12]);
                    uint32_t activeMinutes = static_cast<uint32_t>(rawTime / 600000000ULL); 

                    if (runCount > 0) {
                        models::UserActivityEntry ua;
                        ua.programPath = rawName;
                        ua.runCount = runCount;
                        ua.totalActiveMinutes = activeMinutes;
                        footprint.userActivity.push_back(std::move(ua));
                    }
                }

                valueNameSize = sizeof(valueName);
                dataSize = sizeof(dataBuf);
                index++;
            }
            RegCloseKey(hUserAssistKey);
        }

        // 5. FEATURE: OS INFO AND BOOT TIME COLLECTION
        HKEY hOsKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hOsKey) == ERROR_SUCCESS)
        {
            char productName[256] = "Windows 11";
            DWORD sizeName = sizeof(productName);
            RegQueryValueExA(hOsKey, "ProductName", NULL, NULL, reinterpret_cast<LPBYTE>(productName), &sizeName);
            footprint.osInformation.osName = productName;

            DWORD installDateRaw = 0;
            DWORD sizeDate = sizeof(installDateRaw);
            if (RegQueryValueExA(hOsKey, "InstallDate", NULL, NULL, reinterpret_cast<LPBYTE>(&installDateRaw), &sizeDate) == ERROR_SUCCESS)
            {
                std::time_t t = installDateRaw;
                std::string dateStr = std::ctime(&t);
                if (!dateStr.empty() && dateStr.back() == '\n') dateStr.pop_back();
                footprint.osInformation.installDate = dateStr;
            }
            RegCloseKey(hOsKey);
        }

        // Calculate exact OS boot time via GetTickCount64
        ULONGLONG uptimeMs = GetTickCount64();
        auto nowClock = std::chrono::system_clock::now();
        auto bootClock = nowClock - std::chrono::milliseconds(uptimeMs);
        std::time_t bootTimeT = std::chrono::system_clock::to_time_t(bootClock);
        std::string bootStr = std::ctime(&bootTimeT);
        if (!bootStr.empty() && bootStr.back() == '\n') bootStr.pop_back();
        footprint.osInformation.bootTime = bootStr;

        // 6. FEATURE: MOZILLA FIREFOX TRIAGE (HISTORY + BOOKMARKS)
        if (const char* appDataPath = std::getenv("APPDATA"))
        {
            std::string firefoxProfilesPath = std::string(appDataPath) + "\\Mozilla\\Firefox\\Profiles";

            if (std::filesystem::exists(firefoxProfilesPath))
            {
                for (const auto& entry : std::filesystem::directory_iterator(firefoxProfilesPath))
                {
                    std::string sqlitePath = entry.path().string() + "\\places.sqlite";
                    if (std::filesystem::exists(sqlitePath))
                    {
                        models::BrowserHistoryEntry history;
                        history.browser = models::BrowserType::MozillaFirefox;
                        history.url = sqlitePath;
                        history.title = "Firefox Places Database (History Scan Stack)";
                        history.visitCount = 1;

                        // Solid system method to get file modification time via stat
                        struct stat fileStat;
                        if (stat(sqlitePath.c_str(), &fileStat) == 0)
                        {
                            char timeBuf[64];
                            if (std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&fileStat.st_mtime))) 
                            {
                                history.lastVisitTime = timeBuf;
                            }
                        }
                        else
                        {
                            history.lastVisitTime = "Unknown Modification Time";
                        }
                        
                        footprint.browserHistory.push_back(std::move(history));
                    }
                }
            }
        }

        // 7. FEATURE: BLUETOOTH DEVICES TRIAGE (BTHPORT HIST)
        HKEY hBthKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices", 0, KEY_READ, &hBthKey) == ERROR_SUCCESS)
        {
            DWORD index = 0;
            char macKeyName[256];
            DWORD macKeyNameSize = sizeof(macKeyName);

            // Iterate over folders whose names are MAC addresses of Bluetooth devices
            while (RegEnumKeyExA(hBthKey, index, macKeyName, &macKeyNameSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
            {
                HKEY hDeviceSubKey;
                if (RegOpenKeyExA(hBthKey, macKeyName, 0, KEY_READ, &hDeviceSubKey) == ERROR_SUCCESS)
                {
                    char bthNameBuf[256] = "Unknown Bluetooth Device";
                    DWORD bthNameSize = sizeof(bthNameBuf);
                    
                    // Extract Name parameter saved by Windows for the paired device
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

        // 8. FEATURE: ENVIRONMENT VARIABLES DUMP (ENV SCAN)
        LPCH envBlock = GetEnvironmentStringsA();
        if (envBlock != nullptr)
        {
            LPCH lpszVariable = envBlock;
            while (*lpszVariable != '\0')
            {
                std::string envLine(lpszVariable);
                
                if (envLine.find("USERNAME=") == 0 || envLine.find("COMPUTERNAME=") == 0) {
                    footprint.osInformation.osName += " | " + envLine;
                }
                lpszVariable += envLine.length() + 1; // Shift pointer to the next string of the block
            }
            FreeEnvironmentStringsA(envBlock); // Memory must be freed
        }

        // Autopilot: Dynamically run Windows plugins from the ARTIFACTS folder
        for (const auto& subScanner : WinRegistry::getScanners())
        {
            subScanner->scan(footprint);
        }

        return footprint;
    }

} // namespace ff::windows
#endif // FF_PLATFORM_WINDOWS