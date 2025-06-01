# DebuggerEngine/tests/CMakeLists.txt
cmake_minimum_required(VERSION 3.10)
project(DebuggerEngineTests LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. Add the test_target executable.
add_executable(test_target PtraceController/test_target.cpp)

# --- FLAGS FOR test_target ---
# Add -fno-pie as a compile option for test_target
target_compile_options(test_target PRIVATE -fno-pie)
# Add -no-pie as a link option for test_target
target_link_options(test_target PRIVATE -no-pie)
# -----------------------------------

# 2. Add your custom test runner executable.
add_executable(ptrace_controller_tests PtraceController/test_ptrace_controller.cpp)

# 3. Pass the path of `test_target` to your test code via a preprocessor macro.
target_compile_definitions(ptrace_controller_tests
    PRIVATE
        TEST_TARGET_PATH="$<TARGET_FILE:test_target>"
)

# 4. Link the test runner against your engine library and pthread
target_link_libraries(ptrace_controller_tests
    PRIVATE
        DebuggerEngine
        pthread
)

# 5. Make sure test_target is built before running tests
add_dependencies(ptrace_controller_tests test_target)

# 6. Add the test to CTest so you can run it with the `ctest` command.
add_test(
    NAME PtraceControllerTests
    COMMAND ptrace_controller_tests
)

# 7. Set test properties (optional but useful)
set_tests_properties(PtraceControllerTests
    PROPERTIES
        TIMEOUT 60  # 60 second timeout
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
)

# 8. Enable testing
enable_testing()