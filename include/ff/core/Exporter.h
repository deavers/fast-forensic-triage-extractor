#pragma once
#include <string_view>
#include <vector>
#include "ff/models/ProcessInfo.h"
#include "ff/models/NetworkConn.h"
#include "ff/models/PersistenceEntry.h"
#include "ff/models/ServiceInfo.h"
#include "ff/models/ForensicArtifacts.h"

namespace ff::core
{
    class Exporter
    {
    public:
        static bool saveToJson(
            std::string_view outputPath,
            const std::vector<models::ProcessInfo>& procs,
            const std::vector<models::PersistenceEntry>& autostarts,
            const std::vector<models::NetworkConn>& connections,
            const std::vector<models::ServiceInfo>& services,
            const models::DigitalFootprint& footprint
        );
    };
} // namespace ff::core