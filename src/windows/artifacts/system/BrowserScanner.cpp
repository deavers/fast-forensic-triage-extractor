#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <filesystem>
#include <string>
#include <sys/stat.h>
#include <cstdlib>

namespace ff::windows
{
    class BrowserScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            if (const char* appDataPath = std::getenv("APPDATA"))
            {
                std::string firefoxProfilesPath = std::string(appDataPath) + "\\Mozilla\\Firefox\\Profiles";
                std::error_code ec; // If the directory doesn't exist

                if (std::filesystem::exists(firefoxProfilesPath, ec))
                {
                    for (const auto& entry : std::filesystem::directory_iterator(firefoxProfilesPath, ec))
                    {
                        std::string sqlitePath = entry.path().string() + "\\places.sqlite";
                        
                        if (std::filesystem::exists(sqlitePath, ec))
                        {
                            models::BrowserHistoryEntry history;
                            history.browser = models::BrowserType::MozillaFirefox;
                            history.url = sqlitePath;
                            history.title = "Firefox Places Database (History Scan Stack)";
                            history.visitCount = 1;

                            struct stat fileStat;
                            if (stat(sqlitePath.c_str(), &fileStat) == 0)
                            {
                                char timeBuf[64];
                                if (std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", std::localtime(&fileStat.st_mtime))) 
                                {
                                    history.lastVisitTime = timeBuf;
                                }
                            }
                            else
                            {
                                history.lastVisitTime = "Unknown Modification Time";
                            }
                            
                            footprint.browserHistory.push_back(std::move(history));
                        }
                    }
                }
            }
        }
    };
    REGISTER_WINDOWS_ARTIFACT(BrowserScanner)
}
#endif