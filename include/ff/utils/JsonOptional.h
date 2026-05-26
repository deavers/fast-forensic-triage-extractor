#pragma once
#include "ff/utils/json.hpp"
#include <optional>

namespace nlohmann
{
    template <typename T>
    struct adl_serializer<std::optional<T>>
    {
        // Convert std::optional to JSON (called on save)
        static void to_json(json& j, const std::optional<T>& opt)
        {
            if (opt.has_value())
            {
                j = *opt; // If value exists, write directly
            }
            else
            {
                j = nullptr; // If no value (nullopt), write as null
            }
        }

        // Convert JSON to std::optional (called on read)
        static void from_json(const json& j, std::optional<T>& opt)
        {
            if (j.is_null())
            {
                opt = std::nullopt;
            }
            else
            {
                opt = j.get<T>();
            }
        }
    };
} // namespace nlohmann