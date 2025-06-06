# DebuggerEngine/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(DebuggerEngine VERSION 1.0 LANGUAGES CXX)

find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBDW REQUIRED libdw)

# Enable generation of compile_commands.json
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

# —————————————————————————————————————————————
# Library target
# —————————————————————————————————————————————
add_library(DebuggerEngine SHARED
    #src/DebuggerEngine.cpp
    src/version.cpp
    #src/TargetManager.cpp
    #src/ConfigManager.cpp
    src/IOManager.cpp
    src/PtraceController.cpp
    src/SymbolResolver.cpp
)

# Add Threads::Threads to your library's dependencies
target_link_libraries(DebuggerEngine
    PUBLIC
        Threads::Threads
        ${LIBDW_LIBRARIES}
)

target_compile_features(DebuggerEngine PUBLIC cxx_std_20)

target_include_directories(DebuggerEngine
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        ${LIBDW_INCLUDE_DIRS}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/internal
)

# —————————————————————————————————————————————
# Installation
# —————————————————————————————————————————————
include(GNUInstallDirs)

install(TARGETS DebuggerEngine
    EXPORT DebuggerEngineTargets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(EXPORT DebuggerEngineTargets
    FILE DebuggerEngineConfig.cmake
    NAMESPACE DebuggerEngine::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/DebuggerEngine
)

# —————————————————————————————————————————————
# Tests (not installed)
# —————————————————————————————————————————————
option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# —————————————————————————————————————————————
# Examples (off by default)
# —————————————————————————————————————————————
option(BUILD_EXAMPLES "Build example/demo apps" OFF)
if(BUILD_EXAMPLES)
  add_subdirectory(examples/cli_demo)
  # (you could also add simple_target here if desired)
endif()