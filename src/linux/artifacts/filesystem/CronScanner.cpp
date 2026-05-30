#include "ff/Platform.h"
#ifdef FF_PLATFORM_LINUX

#include "linux/LinuxRegistry.h"
#include <fstream>
#include <string>

namespace ff::linux_os
{
    class CronScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            std::string cronPath = "/etc/crontab";
            std::ifstream cronFile(cronPath);
            
            if (cronFile.is_open())
            {
                std::string line;
                while (std::getline(cronFile, line))
                {
                    // Ignore empty lines, comments, and environment variable settings in the crontab
                    if (line.empty() || line[0] == '#' 
                        || line.find("SHELL=") == 0 || line.find("PATH=") == 0) 
                        continue;

                    models::CronTask task;
                    task.filePath = cronPath;
                    task.taskLine = line;
                    footprint.scheduledTasks.push_back(std::move(task));
                }
            }
        }
    };

    REGISTER_LINUX_ARTIFACT(CronScanner)
}
#endif