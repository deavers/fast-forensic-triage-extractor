cmake_minimum_required(VERSION 3.20)
project(fastforensics CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Basic independent sources of the cross-platform core
set(CORE_SOURCES
    src/main.cpp
    src/core/Exporter.cpp
    src/utils/ConsolePrinter.cpp  # ИСПРАВЛЕНО: перенесено из src/core в src/utils
)

if(UNIX AND NOT APPLE)
    # Automatically recursively gather ALL .cpp files of the Linux backend and its plugins folder
    file(GLOB_RECURSE LINUX_SOURCES 
        "src/linux/*.cpp"
        "src/linux/artifacts/*.cpp"
    )
    
    add_executable(fastforensics ${CORE_SOURCES} ${LINUX_SOURCES})
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_LINUX)
    
    # FORCE LINUX LINKER TO KEEP SELF-REGISTERING PLUGINS (Fixes 0 artifacts bug)
    target_link_options(fastforensics PRIVATE "-Wl,--whole-archive" "-Wl,--no-whole-archive")

elseif(WIN32)
    # Automatically recursively gather ALL .cpp files of the Windows backend and its plugins folder
    file(GLOB_RECURSE WIN_SOURCES 
        "src/windows/*.cpp"
        "src/windows/artifacts/*.cpp"
    )
    
    # Strictly compile ONLY core and Windows specific artifacts (No Linux files mixed here!)
    add_executable(fastforensics ${CORE_SOURCES} ${WIN_SOURCES})
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_WINDOWS)
    
    # System libraries for WinAPI low-level forensic functions for network, events, and signatures
    target_link_libraries(fastforensics PRIVATE ws2_32 iphlpapi wbemuuid ole32 oleaut32 wintrust wevtapi psapi)
endif()

# Strict code quality flags (Warnings are treated as compilation errors)
target_compile_options(fastforensics PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Werror>
)

target_include_directories(fastforensics PRIVATE include src)

# STATIC LINKING FOR ZERO-DEPENDENCY DFIR TOOL
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(fastforensics PRIVATE "-static" "-static-libgcc" "-static-libstdc++")
endif()