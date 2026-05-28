#pragma once
#include "ff/models/ForensicArtifacts.h"

namespace ff::core
{
    // Interface for atomic artifact scanners
    class IArtifactSubScanner
    {
    public:
        virtual ~IArtifactSubScanner() = default;
        
        // Each function receives a reference to the report and populates it with its own data
        virtual void scan(models::DigitalFootprint& footprint) const = 0;
    };
}