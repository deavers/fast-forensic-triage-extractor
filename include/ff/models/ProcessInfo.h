#pragma once
#include <string>
#include <cstdint>
#include <optional>

#include "ff/utils/json.hpp"
#include "ff/utils/JsonOptional.h"

namespace ff::models
{
    struct ProcessInfo 
    {
        uint32_t    pid;
        uint32_t    ppid;
        std::string name;
        uint64_t    memoryKB;
        bool        isElevated;
        bool isSignatureValid = false;

        std::optional<std::string> exePath;
        std::optional<std::string> username;
        std::optional<std::string> cmdLine;

        [[nodiscard]] bool isAccessible() const
        {
            return exePath.has_value() && !exePath->empty();
        }

        // Serialization for JSON export
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ProcessInfo, pid, ppid, name, exePath, memoryKB, isElevated, isSignatureValid)
    };
}