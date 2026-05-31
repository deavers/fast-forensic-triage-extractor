#pragma once
#include "ff/models/ForensicArtifacts.h"
#include <string_view>

namespace ff::core
{
    class Exporter
    {
    public:
        static bool saveToJson(
            std::string_view outputPath,
            const models::DigitalFootprint& footprint
        );
    };
}