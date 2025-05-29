# DebuggerEngine/examples/cli_demo/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(cli_demo LANGUAGES CXX)

add_executable(cli_demo
    main.cpp
)

target_link_libraries(cli_demo
    PRIVATE DebuggerEngine
)

target_include_directories(cli_demo
    PRIVATE ${CMAKE_SOURCE_DIR}/include
)