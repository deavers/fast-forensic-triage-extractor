#include "ff/core/Exporter.h"
#include "ff/utils/json.hpp"
#include <fstream>
#include <chrono>

// Explicitly include all models so the compiler sees their fields
#include "ff/models/ProcessInfo.h"
#include "ff/models/NetworkConn.h"
#include "ff/models/PersistenceEntry.h"
#include "ff/models/ServiceInfo.h"
#include "ff/models/ForensicArtifacts.h"

namespace ff::core
{
    namespace
    {
        // Manual conversion functions (fighting MSVC compiler quirks)
        nlohmann::json processTo_json(const models::ProcessInfo& p)
        {
            nlohmann::json j;
            j["pid"] = p.pid;
            j["ppid"] = p.ppid;
            j["name"] = p.name;
            
            if (p.exePath) {
                j["exePath"] = *p.exePath;
            } else {
                j["exePath"] = nullptr;
            }
            
            j["memoryKB"] = p.memoryKB;
            j["isElevated"] = p.isElevated;
            j["isSignatureValid"] = p.isSignatureValid;
            return j;
        }

        nlohmann::json networkTo_json(const models::NetworkConn& c)
        {
            std::string stateStr = "UNKNOWN";
            if (c.state == models::State::Listen) stateStr = "LISTEN";
            else if (c.state == models::State::Established) stateStr = "ESTABLISHED";
            else if (c.state == models::State::TimeWait) stateStr = "TIME_WAIT";
            else if (c.state == models::State::CloseWait) stateStr = "CLOSE_WAIT";

            nlohmann::json j;
            j["protocol"] = (c.protocol == models::Protocol::TCP ? "TCP" : "UDP");
            j["localAddr"] = c.localAddr;
            j["localPort"] = c.localPort;
            j["remoteAddr"] = c.remoteAddr;
            j["remotePort"] = c.remotePort;
            j["state"] = stateStr;
            
            // Fixed: Avoid ternary for ownerPid as well
            if (c.ownerPid) {
                j["ownerPid"] = *c.ownerPid;
            } else {
                j["ownerPid"] = nullptr;
            }
            
            j["uid"] = c.uid;
            return j;
        }

        nlohmann::json persistenceTo_json(const models::PersistenceEntry& e)
        {
            return nlohmann::json{
                {"type", e.type == models::PersistenceType::RegistryRun ? "RegistryRun" : "ScheduledTask"},
                {"name", e.name},
                {"trigger", e.trigger},
                {"imagePath", e.imagePath}
            };
        }

        nlohmann::json serviceTo_json(const models::ServiceInfo& s)
        {
            return nlohmann::json{
                {"name", s.name},
                {"displayName", s.displayName},
                {"imagePath", s.imagePath},
                {"startType", s.startType},
                {"serviceType", s.serviceType}
            };
        }
    }

    bool Exporter::saveToJson(
        std::string_view outputPath,
        const std::vector<models::ProcessInfo>& procs,
        const std::vector<models::PersistenceEntry>& autostarts,
        const std::vector<models::NetworkConn>& connections,
        const std::vector<models::ServiceInfo>& services,
        const models::DigitalFootprint& footprint
    )
    {
        nlohmann::json report;

        // Report metadata
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        
        report["metadata"]["tool_name"] = "Fast Forensic Triage Extractor (FFTE)";
        report["metadata"]["version"] = "1.0.0-Epoch1";

        // Safe time formatting, remove newline from ctime
        std::string timeStr = std::ctime(&now_time);
        if (!timeStr.empty() && timeStr.back() == '\n') timeStr.pop_back();
        report["metadata"]["scan_timestamp"] = timeStr;

        report["artifacts"]["digital_footprint"]["hw_info"] = {
            {"cpuName", footprint.hw_info.cpuName},
            {"gpuName", footprint.hw_info.gpuName},
            {"totalRamGB", footprint.hw_info.totalRamGB},
            {"motherboardSerial", footprint.hw_info.motherboardSerial}
        };

        // Populate process array
        report["artifacts"]["processes"] = nlohmann::json::array();
        for (const auto& p : procs) {
            report["artifacts"]["processes"].push_back(processTo_json(p));
        }

        // Autostarts / Persistence
        report["artifacts"]["persistence"] = nlohmann::json::array();
        for (const auto& e : autostarts) {
            report["artifacts"]["persistence"].push_back(persistenceTo_json(e));
        }

        // Network connections
        report["artifacts"]["network_connections"] = nlohmann::json::array();
        for (const auto& c : connections) {
            report["artifacts"]["network_connections"].push_back(networkTo_json(c));
        }

        // Services and drivers
        report["artifacts"]["services_and_drivers"] = nlohmann::json::array();
        for (const auto& s : services) {
            report["artifacts"]["services_and_drivers"].push_back(serviceTo_json(s));
        }

        // Digital footprint (USB, Location, VPN)
        report["artifacts"]["digital_footprint"]["anonymity"]["isProxyActive"] = footprint.anonymity.isProxyActive;
        report["artifacts"]["digital_footprint"]["anonymity"]["isVpnActive"] = footprint.anonymity.isVpnActive;
        report["artifacts"]["digital_footprint"]["anonymity"]["activeAdapters"] = footprint.anonymity.activeAdapters;
        
        report["artifacts"]["digital_footprint"]["location"]["latitude"] = footprint.location.latitude;
        report["artifacts"]["digital_footprint"]["location"]["longitude"] = footprint.location.longitude;
        report["artifacts"]["digital_footprint"]["location"]["source"] = footprint.location.source;

        report["artifacts"]["digital_footprint"]["usb_history"] = nlohmann::json::array();
        for (const auto& usb : footprint.usbHistory) {
            report["artifacts"]["digital_footprint"]["usb_history"].push_back({
                {"deviceInstanceId", usb.deviceInstanceId},
                {"friendlyName", usb.friendlyName}
            });
        }

        report["artifacts"]["digital_footprint"]["user_activity"] = nlohmann::json::array();
        for (const auto& ua : footprint.userActivity) {
            report["artifacts"]["digital_footprint"]["user_activity"].push_back({
                {"programPath", ua.programPath},
                {"runCount", ua.runCount},
                {"totalActiveMinutes", ua.totalActiveMinutes} // minutes json
            });
        }

        report["artifacts"]["digital_footprint"]["os_info"]["name"] = footprint.osInformation.osName;
        report["artifacts"]["digital_footprint"]["os_info"]["install_date"] = footprint.osInformation.installDate;
        report["artifacts"]["digital_footprint"]["os_info"]["boot_time"] = footprint.osInformation.bootTime;

        report["artifacts"]["digital_footprint"]["browser_history"] = nlohmann::json::array();
        for (const auto& b : footprint.browserHistory) {
            report["artifacts"]["digital_footprint"]["browser_history"].push_back({
                {"browser", b.browser == models::BrowserType::MozillaFirefox ? "MozillaFirefox" : "Other"},
                {"url", b.url},
                {"title", b.title},
                {"visitCount", b.visitCount},
                {"lastVisitTime", b.lastVisitTime}
            });
        }

        report["artifacts"]["digital_footprint"]["bluetooth_history"] = nlohmann::json::array();
        for (const auto& b : footprint.bluetoothHistory) {
            report["artifacts"]["digital_footprint"]["bluetooth_history"].push_back({
                {"name", b.name},
                {"macAddress", b.macAddress}
            });
        }

        for (const auto& env : footprint.processEnvironments) {
            report["artifacts"]["digital_footprint"]["process_environments"].push_back({
                {"pid", env.pid},
                {"envDump", env.envDump}
            });
        }

        for (const auto& fd : footprint.processFileDescriptors) {
            report["artifacts"]["digital_footprint"]["process_open_files"].push_back({
                {"pid", fd.pid},
                {"openFiles", fd.openFiles}
            });
        }

        for (const auto& cred : footprint.processCredentials) {
            report["artifacts"]["digital_footprint"]["process_credentials"].push_back({
                {"pid", cred.pid},
                {"uid_info", cred.uid_info},
                {"gid_info", cred.gid_info}
            });
        }

        for (const auto& cg : footprint.processCgroups) {
            report["artifacts"]["digital_footprint"]["process_cgroups"].push_back({
                {"pid", cg.pid},
                {"containerPath", cg.containerPath},
                {"isContainerized", cg.isContainerized}
            });
        }

        for (const auto& pf : footprint.prefetchFiles) {
            report["artifacts"]["digital_footprint"]["prefetch_files"].push_back({
                {"executableName", pf.executableName},
                {"prefetchFileName", pf.prefetchFileName},
                {"lastRunTime", pf.lastRunTime}
            });
        }

        // Save file to disk
        std::ofstream file(std::string{outputPath});
        if (!file.is_open()) return false;

        file << report.dump(4);
        file.close();
        return true;
    }
} // namespace ff::core