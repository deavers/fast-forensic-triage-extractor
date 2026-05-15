cmake_minimum_required(VERSION 3.20)
project(fastforensics CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(fastforensics
    src/main.cpp
    src/core/Exporter.cpp
)

if(UNIX AND NOT APPLE)
    target_sources(fastforensics PRIVATE
        src/linux/LinuxSystemScanner.cpp
        src/linux/LinuxNetworkScanner.cpp
    )
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_LINUX)
elseif(WIN32)
    target_sources(fastforensics PRIVATE
        src/windows/WinSystemScanner.cpp
    )
    target_compile_definitions(fastforensics PRIVATE FF_PLATFORM_WINDOWS)
    
    target_link_libraries(fastforensics PRIVATE iphlpapi ws2_32 ntdll wintrust)
endif()

target_include_directories(fastforensics PRIVATE include)