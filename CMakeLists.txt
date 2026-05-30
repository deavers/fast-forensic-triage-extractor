cmake_minimum_required(VERSION 3.20)
project(fastforensics CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Basic independent sources of the cross-platform core
set(CORE_SOURCES
    src/main.cpp
    src/core/Exporter.cpp
    src/core/ConsolePrinter.cpp
)

if(UNIX AND NOT APPLE)
    # Automatically recursively gather ALL .cpp files of the Linux backend and its plugins folder
    file(GLOB_RECURSE LINUX_ARTIFACTS_SOURCES 
        "src/linux/artifacts/*.cpp"
        "src/linux/*.cpp"
    )
    list(APPEND LINUX_SOURCES ${LINUX_ARTIFACTS_SOURCES})
    
    add_executable(fastforensics ${CORE_SOURCES} ${LINUX_SOURCES})
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_LINUX)

elseif(WIN32)
    # Automatically recursively gather ALL .cpp files of the Windows backend and its plugins folder
    file(GLOB_RECURSE WINDOWS_ARTIFACTS_SOURCES 
        "src/windows/artifacts/*.cpp"
        "src/windows/*.cpp"
    )
    list(APPEND WIN_SOURCES ${WINDOWS_ARTIFACTS_SOURCES})
    
    add_executable(fastforensics ${CORE_SOURCES} ${WIN_SOURCES}
        src/linux/artifacts/filesystem/SshKeyScanner.cpp
        src/windows/WinRegistry.h
        src/linux/artifacts/process/ProcEnvScanner.cpp
        src/linux/artifacts/process/ProcFdScanner.cpp
        src/linux/artifacts/process/ProcCredScanner.cpp
        src/linux/artifacts/process/CgroupScanner.cpp)
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_WINDOWS)
    
    # System libraries for WinAPI low-level forensic functions for network and signatures
    target_link_libraries(fastforensics PRIVATE iphlpapi ws2_32 ntdll wintrust)
endif()

# Strict code quality flags (Warnings are treated as compilation errors)
target_compile_options(fastforensics PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -Werror>
)

target_include_directories(fastforensics PRIVATE include src)