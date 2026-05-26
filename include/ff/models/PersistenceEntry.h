#pragma once
#include <string>

#include "ff/utils/json.hpp"

namespace ff::models
{
    enum class PersistenceType
    {
        RegistryRun,   // HKLM\Software\Microsoft\Windows\CurrentVersion\Run
        ScheduledTask
    };

    struct PersistenceEntry
    {
        PersistenceType type;
        std::string     name;        // Name of the entry (e.g., registry key name or scheduled task name)
        std::string     trigger;     // What triggers the entry (e.g., "At startup" or path to the registry key)
        std::string     imagePath;   // Path to the executable that is set to run
    };

    // Serialization for JSON export
    NLOHMANN_JSON_SERIALIZE_ENUM(PersistenceType, {
        {PersistenceType::RegistryRun, "RegistryRun"},
        {PersistenceType::ScheduledTask, "ScheduledTask"}
    })

    NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(PersistenceEntry, type, name, trigger, imagePath)
} // namespace ff::models