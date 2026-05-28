#pragma once
#include "ff/models/ForensicArtifacts.h"

namespace ff::utils
{
    class ConsolePrinter
    {
    public:
        // Main entry point for printing the forensic report to the console
        static void printForensicReport(const models::DigitalFootprint& footprint);

    private:
        // Izolated printing
        static void printCommonData(const models::DigitalFootprint& footprint);
        static void printLinuxSpecifics(const models::DigitalFootprint& footprint);
        static void printWindowsSpecifics(const models::DigitalFootprint& footprint);
    };
}