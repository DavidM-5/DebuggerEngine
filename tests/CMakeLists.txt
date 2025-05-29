# DebuggerEngine/tests/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(DebuggerEngineTests LANGUAGES CXX)

find_package(GTest REQUIRED)
include(GoogleTest)

add_executable(DebuggerEngineTests
    #DebuggerEngineTests.cpp
    #TargetManagerTests.cpp
)

target_link_libraries(DebuggerEngineTests
    PRIVATE
      DebuggerEngine
      GTest::gtest_main
)

target_include_directories(DebuggerEngineTests
    PRIVATE
      ${CMAKE_SOURCE_DIR}/include
)

gtest_discover_tests(DebuggerEngineTests)