#pragma once
#include <string>
#include <cstdint>
#include <optional>

#include "ff/utils/json.hpp"
#include "ff/utils/JsonOptional.h"

namespace ff::models
{
    enum class Protocol
    {
        TCP,
        UDP, 
        TCP6,
        UDP6
    };

    enum class State
    {
        Listen,       // 0x0A
        Established,  // 0x01
        TimeWait,     // 0x06
        CloseWait,    // 0x08
        Unknown
    };

    struct NetworkConn
    {
        std::string localAddr;
        uint16_t    localPort;

        std::string remoteAddr;
        uint16_t    remotePort;

        State       state;
        Protocol    protocol;

        uint32_t    uid;
        std::optional<uint32_t> ownerPid;

        [[nodiscard]] bool isListening() const
        {
            return state == State::Listen;
        }

        // Serialization for JSON export
        NLOHMANN_JSON_SERIALIZE_ENUM(Protocol, {
            {Protocol::TCP, "TCP"},
            {Protocol::UDP, "UDP"}
        })

        NLOHMANN_JSON_SERIALIZE_ENUM(State, {
            {State::Unknown, "UNKNOWN"},
            {State::Listen, "LISTEN"},
            {State::Established, "ESTABLISHED"},
            {State::TimeWait, "TIME_WAIT"},
            {State::CloseWait, "CLOSE_WAIT"}
        })

        // Serialize struct (nlohmann supports std::optional for ownerPid out of the box)
        NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(NetworkConn, protocol, localAddr, localPort, remoteAddr, remotePort, state, ownerPid, uid)

    };
}