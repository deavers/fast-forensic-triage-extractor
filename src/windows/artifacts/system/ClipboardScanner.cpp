#include "ff/Platform.h"
#ifdef FF_PLATFORM_WINDOWS

#include "windows/WinRegistry.h"
#include <windows.h>
#include <string>

namespace ff::windows
{
    class ClipboardScanner : public core::IArtifactSubScanner
    {
    public:
        void scan(models::DigitalFootprint& footprint) const override
        {
            if (!OpenClipboard(nullptr)) 
                return;

            // Check if CF_TEXT format is available in the clipboard
            if (IsClipboardFormatAvailable(CF_TEXT))
            {
                HANDLE hData = GetClipboardData(CF_TEXT);
                if (hData != nullptr)
                {
                    // Lock the memory block for reading
                    char* pszText = static_cast<char*>(GlobalLock(hData));
                    if (pszText != nullptr)
                    {
                        SIZE_T size = GlobalSize(hData);
                        
                        models::ClipboardEntry entry;
                        entry.format = "CF_TEXT (Plain Text)";
                        entry.sizeBytes = std::to_string(size) + " bytes";
                        
                        // Protection from too large data in the buffer (limit to 5 KB for JSON)
                        std::string content(pszText);
                        if (content.length() > 5120) 
                            entry.content = content.substr(0, 5120) + "... [TRUNCATED]";
                        else 
                            entry.content = content;
                        
                        footprint.clipboardData.push_back(std::move(entry));
                        
                        GlobalUnlock(hData);
                    }
                }
            }
            CloseClipboard();
        }
    };

    REGISTER_WINDOWS_ARTIFACT(ClipboardScanner)
}
#endif