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
            
            if (p.exePath) 
            {
                j["exePath"] = *p.exePath;
            } 
            else 
            {
                j["exePath"] = nullptr;
            }
            
            j["memoryKB"] = p.memoryKB;
            j["isElevated"] = p.isElevated;
            j["isSignatureValid"] = p.isSignatureValid;
            j["sha256Hash"] = p.sha256Hash;
            return j;
        }

        nlohmann::json persistenceTo_json(const models::PersistenceEntry& e)
        {
            return nlohmann::json
            {
                {"type", e.type == models::PersistenceType::RegistryRun ? "RegistryRun" : "ScheduledTask"},
                {"name", e.name},
                {"trigger", e.trigger},
                {"imagePath", e.imagePath}
            };
        }

        nlohmann::json serviceTo_json(const models::ServiceInfo& s)
        {
            return nlohmann::json
            {
                {"name", s.name},
                {"displayName", s.displayName},
                {"imagePath", s.imagePath},
                {"startType", s.startType},
                {"serviceType", s.serviceType}
            };
        }
    }

    bool Exporter::saveToJson(std::string_view outputPath, const models::DigitalFootprint& footprint)
    {
        nlohmann::json report;
        auto now = std::chrono::system_clock::now();
        std::time_t now_time = std::chrono::system_clock::to_time_t(now);
        std::string timeStr = std::ctime(&now_time);
        
        if (!timeStr.empty() && timeStr.back() == '\n') 
            timeStr.pop_back();
        
        report["metadata"]["tool_name"] = "Fast Forensic Triage Extractor (FFTE)";
        report["metadata"]["version"] = "1.0.0-Epoch1";
        report["metadata"]["scan_timestamp"] = timeStr;

        // Hardware, OS & Location
        report["artifacts"]["digital_footprint"]["os_info"] = 
        {
            {"name", footprint.osInformation.osName},
            {"install_date", footprint.osInformation.installDate},
            {"boot_time", footprint.osInformation.bootTime}
        };
        report["artifacts"]["digital_footprint"]["hw_info"] = 
        {
            {"cpuName", footprint.hw_info.cpuName}, {"gpuName", footprint.hw_info.gpuName},
            {"totalRamGB", footprint.hw_info.totalRamGB}, {"motherboardSerial", footprint.hw_info.motherboardSerial}
        };
        report["artifacts"]["digital_footprint"]["location"] = 
        {
            {"latitude", footprint.location.latitude}, {"longitude", footprint.location.longitude}, {"source", footprint.location.source}
        };
        report["artifacts"]["digital_footprint"]["anonymity"] = 
        {
            {"isProxyActive", footprint.anonymity.isProxyActive}, {"isVpnActive", footprint.anonymity.isVpnActive}, {"activeAdapters", footprint.anonymity.activeAdapters}
        };

        // Web & Browser
        for (const auto& b : footprint.browserHistory) 
        {
            report["artifacts"]["digital_footprint"]["browser_history"].push_back({
                {"browser", b.browser == models::BrowserType::MozillaFirefox ? "MozillaFirefox" : "Other"},
                {"url", b.url}, {"title", b.title}, {"visitCount", b.visitCount}, {"lastVisitTime", b.lastVisitTime}
            });
        }
        for (const auto& ext : footprint.browserExtensions) 
        {
            report["artifacts"]["digital_footprint"]["browser_extensions"].push_back({
                {"browser", ext.browser}, {"extensionId", ext.extensionId}, {"updateUrl", ext.updateUrl}
            });
        }
        for (const auto& dns : footprint.dnsCache) 
        {
            report["artifacts"]["digital_footprint"]["dns_cache"].push_back({
                {"recordName", dns.recordName}, {"recordType", dns.recordType}, {"data", dns.data}
            });
        }

        // Network & System Files
        for (const auto& conn : footprint.networkConnections) 
        {
            report["artifacts"]["digital_footprint"]["network_connections"].push_back({
                {"protocol", conn.protocol}, {"localIp", conn.localIp}, {"localPort", conn.localPort},
                {"remoteIp", conn.remoteIp}, {"remotePort", conn.remotePort}, {"state", conn.state}
            });
        }
        for (const auto& sf : footprint.systemFiles) 
        {
            report["artifacts"]["digital_footprint"]["system_files"].push_back({
                {"fileName", sf.fileName}, {"sizeMB", sf.sizeMB}, {"notes", sf.notes}
            });
        }

        // Processes & Memory
        for (const auto& p : footprint.processes) report["artifacts"]["processes"].push_back(processTo_json(p));
        for (const auto& mem : footprint.injectedMemory) 
        {
            report["artifacts"]["digital_footprint"]["injected_memory"].push_back({
                {"pid", mem.pid}, {"processName", mem.processName}, {"memoryAddress", mem.memoryAddress}, {"protection", mem.protection}
            });
        }

        // Persistence
        for (const auto& e : footprint.persistence) report["artifacts"]["persistence"].push_back(persistenceTo_json(e));
        for (const auto& s : footprint.services) report["artifacts"]["services_and_drivers"].push_back(serviceTo_json(s));
        for (const auto& cron : footprint.scheduledTasks) 
        {
            report["artifacts"]["digital_footprint"]["scheduled_tasks"].push_back({
                {"filePath", cron.filePath}, {"taskLine", cron.taskLine}
            });
        }

        // Security Logs & Exfiltration
        for (const auto& evt : footprint.eventLogs) 
        {
            report["artifacts"]["digital_footprint"]["event_logs"].push_back({
                {"eventId", evt.eventId}, {"timestamp", evt.timestamp}, {"details", evt.details}
            });
        }
        for (const auto& clip : footprint.clipboardData) 
        {
            report["artifacts"]["digital_footprint"]["clipboard_triage"].push_back({
                {"format", clip.format}, {"sizeBytes", clip.sizeBytes}, {"content", clip.content}
            });
        }

        // ----------------------------------------------------
        // --- MISSING WINDOWS ARTIFACTS ---
        // ----------------------------------------------------
        for (const auto& arp : footprint.arpEntries) {
            report["artifacts"]["digital_footprint"]["arp_entries"].push_back({
                {"ipAddress", arp.ipAddress}, {"macAddress", arp.macAddress}, {"type", arp.type}
            });
        }
        for (const auto& fw : footprint.firewallRules) {
            report["artifacts"]["digital_footprint"]["firewall_rules"].push_back({
                {"ruleName", fw.ruleName}, {"ruleData", fw.ruleData}
            });
        }
        for (const auto& pf : footprint.prefetchFiles) {
            report["artifacts"]["digital_footprint"]["prefetch_files"].push_back({
                {"executableName", pf.executableName}, {"prefetchFileName", pf.prefetchFileName}, {"lastRunTime", pf.lastRunTime}
            });
        }
        for (const auto& rdp : footprint.rdpSessions) {
            report["artifacts"]["digital_footprint"]["rdp_sessions"].push_back({
                {"targetHost", rdp.targetHost}, {"usernameHint", rdp.usernameHint}
            });
        }
        for (const auto& usb : footprint.usbHistory) {
            report["artifacts"]["digital_footprint"]["usb_history"].push_back({
                {"deviceInstanceId", usb.deviceInstanceId}, {"friendlyName", usb.friendlyName}
            });
        }

        // ----------------------------------------------------
        // --- LINUX SPECIFIC ARTIFACTS ---
        // ----------------------------------------------------
        for (const auto& mod : footprint.linuxModules) 
        {
            report["artifacts"]["digital_footprint"]["linux_modules"].push_back({
                {"name", mod.name}, {"size", mod.size}, {"state", mod.state}
            });
        }
        for (const auto& key : footprint.sshKeys) 
        {
            report["artifacts"]["digital_footprint"]["ssh_keys"].push_back({
                {"path", key.path}, {"keyContent", key.keyContent}
            });
        }
        for (const auto& fd : footprint.processFileDescriptors) 
        {
            report["artifacts"]["digital_footprint"]["process_open_files"].push_back({
                {"pid", fd.pid}, {"openFiles", fd.openFiles}
            });
        }
        for (const auto& env : footprint.processEnvironments) 
        {
            report["artifacts"]["digital_footprint"]["process_environments"].push_back({
                {"pid", env.pid}, {"environment", env.envDump}
            });
        }
        for (const auto& cred : footprint.processCredentials) 
        {
            report["artifacts"]["digital_footprint"]["process_credentials"].push_back({
                {"pid", cred.pid}, {"uid_info", cred.uid_info}, {"gid_info", cred.gid_info}
            });
        }
        for (const auto& cg : footprint.processCgroups) 
        {
            report["artifacts"]["digital_footprint"]["process_cgroups"].push_back({
                {"pid", cg.pid}, {"cgroup_paths", cg.containerPath}, {"isContainerized", cg.isContainerized}
            });
        }
        for (const auto& pkg : footprint.installedPackages) 
        {
            report["artifacts"]["digital_footprint"]["installed_packages"].push_back({
                {"name", pkg.name}, {"version", pkg.version}
            });
        }
        for (const auto& unit : footprint.systemdUnits) 
        {
            report["artifacts"]["digital_footprint"]["systemd_units"].push_back({
                {"name", unit.name}, {"state", unit.state}
            });
        }

        // Save
        std::ofstream file(std::string{outputPath});
        if (!file.is_open()) 
            return false;
        file << report.dump(4, ' ', false, nlohmann::json::error_handler_t::replace);
        file.close();

        return true;
    }
} // namespace ff::core