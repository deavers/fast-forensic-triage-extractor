#pragma once
#include <string_view>

namespace ff 
{
    enum class Platform { 
        Linux, 
        Windows, 
        Android, 
        IOS
    };

    #if defined(FF_PLATFORM_LINUX)
        constexpr Platform kCurrentPlatform = Platform::Linux;
        constexpr std::string_view kPlatformName = "linux";
    #elif defined(FF_PLATFORM_WINDOWS)
        constexpr Platform kCurrentPlatform = Platform::Windows;
        constexpr std::string_view kPlatformName = "windows";
    #elif defined(FF_PLATFORM_ANDROID)
        constexpr Platform kCurrentPlatform = Platform::Android;
        constexpr std::string_view kPlatformName = "android";
    #elif defined(FF_PLATFORM_IOS)
        constexpr Platform kCurrentPlatform = Platform::IOS;
        constexpr std::string_view kPlatformName = "ios";
    #endif
}