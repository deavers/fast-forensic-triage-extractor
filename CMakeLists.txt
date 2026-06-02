cmake_minimum_required(VERSION 3.20)
project(fastforensics CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_compile_definitions(_CRT_SECURE_NO_WARNINGS)

# Base sources common to all platforms
set(CORE_SOURCES
    src/main.cpp
    src/core/Exporter.cpp
    src/utils/ConsolePrinter.cpp
)

if(UNIX AND NOT APPLE)
    # Package Linux-specific files recursively
    file(GLOB_RECURSE LINUX_SOURCES "src/linux/*.cpp")
    
    add_executable(fastforensics ${CORE_SOURCES} ${LINUX_SOURCES})
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_LINUX)
    target_link_options(fastforensics PRIVATE "-Wl,--whole-archive" "-Wl,--no-whole-archive")

elseif(WIN32)
    # Package Windows-specific files recursively
    file(GLOB_RECURSE WIN_SOURCES "src/windows/*.cpp")
    
    add_executable(fastforensics ${CORE_SOURCES} ${WIN_SOURCES})
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_WINDOWS)
    
    # System libraries
    target_link_libraries(fastforensics PRIVATE ws2_32 iphlpapi wbemuuid ole32 oleaut32 wintrust wevtapi psapi)
endif()

target_compile_options(fastforensics PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Werror>
)

target_include_directories(fastforensics PRIVATE include src)

# Static linking on Windows with MinGW to avoid dependency issues on target machines
if(WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(fastforensics PRIVATE "-static" "-static-libgcc" "-static-libstdc++")
endif()