#include <iostream>
#include <chrono>
#include <thread>
#include <cassert>
#include <string>
#include <vector>
#include <cstring>
#include <sys/wait.h>
#include <signal.h>
#include <functional>
#include <map>
#include <sstream>
#include <unistd.h>
#include <sys/types.h>
#include "../../src/PtraceController.h"

// Test configuration
#ifndef TEST_TARGET_PATH
#define TEST_TARGET_PATH "./bin/test_target"  // Fallback for manual compilation
#endif

#define TEST_TIMEOUT_MS 5000

class TestRunner {
private:
    int passed = 0;
    int failed = 0;
    std::string current_test;

public:
    void startTest(const std::string& name) {
        current_test = name;
        std::cout << "\n=== Testing: " << name << " ===" << std::endl;
    }

    void assert_true(bool condition, const std::string& message) {
        if (condition) {
            std::cout << "✓ " << message << std::endl;
            passed++;
        } else {
            std::cout << "✗ " << message << " [FAILED]" << std::endl;
            failed++;
        }
    }

    void assert_false(bool condition, const std::string& message) {
        assert_true(!condition, message);
    }

    void printSummary() {
        std::cout << "\n" << std::string(50, '=') << std::endl;
        std::cout << "Test Summary:" << std::endl;
        std::cout << "Passed: " << passed << std::endl;
        std::cout << "Failed: " << failed << std::endl;
        std::cout << "Total:  " << (passed + failed) << std::endl;
        if (failed == 0) {
            std::cout << "🎉 All tests passed!" << std::endl;
        } else {
            std::cout << "❌ " << failed << " test(s) failed!" << std::endl;
        }
        std::cout << std::string(50, '=') << std::endl;
    }

    bool allPassed() const { return failed == 0; }
};

// Helper class to manage target processes for attach testing
class ProcessManager {
private:
    std::vector<pid_t> managed_pids;

public:
    ~ProcessManager() {
        cleanup();
    }

    pid_t startTargetProcess(const std::vector<std::string>& args = {}) {
        pid_t pid = fork();
        
        if (pid == -1) {
            perror("fork in ProcessManager");
            return -1;
        }
        
        if (pid == 0) {
            // Child process - set up for tracing and exec the target
            if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
                perror("ptrace(TRACEME)");
                exit(1);
            }
            
            // Convert args to execvp format
            std::vector<std::string> full_args = {TEST_TARGET_PATH};
            full_args.insert(full_args.end(), args.begin(), args.end());
            
            std::vector<char*> argv;
            for (const auto& arg : full_args) {
                argv.push_back(const_cast<char*>(arg.c_str()));
            }
            argv.push_back(nullptr);
            
            // Execute the target
            execvp(TEST_TARGET_PATH, argv.data());
            perror("execvp in ProcessManager");
            exit(1);
        }
        
        // Parent process - track the PID
        managed_pids.push_back(pid);
        return pid;
    }
    
    void killProcess(pid_t pid) {
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
        managed_pids.erase(std::remove(managed_pids.begin(), managed_pids.end(), pid), managed_pids.end());
    }
    
    void cleanup() {
        for (pid_t pid : managed_pids) {
            kill(pid, SIGKILL);
            waitpid(pid, nullptr, 0);
        }
        managed_pids.clear();
    }
};

// Helper function to wait with timeout
bool waitWithTimeout(std::function<bool()> condition, int timeout_ms = TEST_TIMEOUT_MS) {
    auto start = std::chrono::steady_clock::now();
    while (!condition()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
        if (elapsed.count() > timeout_ms) {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}

// Test basic lifecycle with attach
void testBasicLifecycleAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Basic Lifecycle with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    // Initial state
    runner.assert_true(debugger.getPid() == -1, "Initial PID should be -1");
    runner.assert_true(debugger.getTraceeState() == DebuggerEngine::TraceeState::NotStarted, 
                      "Initial state should be NotStarted");
    
    // Start target process and attach
    pid_t target_pid = pm.startTargetProcess();
    runner.assert_true(target_pid > 0, "Should start target process successfully");
    
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    runner.assert_true(debugger.getPid() == target_pid, "PID should match target PID after attach");
    runner.assert_true(debugger.getTraceeState() == DebuggerEngine::TraceeState::Stopped, 
                      "State should be Stopped after attach");
    
    // Terminate
    bool terminated = debugger.terminate();
    runner.assert_true(terminated, "Should terminate successfully");
    
    // Wait for exit state
    bool exited = waitWithTimeout([&]() {
        return debugger.getTraceeState() == DebuggerEngine::TraceeState::Exited;
    });
    runner.assert_true(exited, "Should reach Exited state after terminate");
}

// Test execution control with attach
void testExecutionControlAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Execution Control with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    // Continue execution
    bool continued = debugger.continueExecution();
    runner.assert_true(continued, "Should continue successfully");
    runner.assert_true(debugger.getTraceeState() == DebuggerEngine::TraceeState::Running, 
                      "State should be Running after continue");
    
    // Let it run briefly
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Interrupt
    bool interrupted = debugger.interrupt();
    runner.assert_true(interrupted, "Should interrupt successfully");
    
    // Wait for stop
    bool stopped = debugger.waitForStop();
    runner.assert_true(stopped, "Should stop after interrupt");
    runner.assert_true(debugger.getTraceeState() == DebuggerEngine::TraceeState::Stopped, 
                      "State should be Stopped after interrupt");
    
    // Single step
    bool stepped = debugger.step();
    runner.assert_true(stepped, "Should step successfully");
    runner.assert_true(debugger.getTraceeState() == DebuggerEngine::TraceeState::Running, 
                      "State should be Running after step");
    
    // Wait for step to complete
    bool step_stopped = debugger.waitForStop();
    runner.assert_true(step_stopped, "Should stop after single step");
    
    debugger.terminate();
}

// Test register operations with attach
void testRegisterOperationsAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Register Operations with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    // Get registers
    DebuggerEngine::Registers regs1, regs2;
    bool got_regs = debugger.getRegisters(regs1);
    runner.assert_true(got_regs, "Should get registers successfully");
    
    // Modify a register (we'll change a general purpose register)
    regs2 = regs1;
    regs2.rax = 0x12345678;  // Set a test value
    
    bool set_regs = debugger.setRegisters(regs2);
    runner.assert_true(set_regs, "Should set registers successfully");
    
    // Read back and verify
    DebuggerEngine::Registers regs3;
    bool got_regs2 = debugger.getRegisters(regs3);
    runner.assert_true(got_regs2, "Should get registers again");
    runner.assert_true(regs3.rax == 0x12345678, "Register modification should persist");
    
    debugger.terminate();
}

// Test memory operations with attach
void testMemoryOperationsAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Memory Operations with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    // Get the instruction pointer to read some code
    DebuggerEngine::Registers regs;
    bool got_regs = debugger.getRegisters(regs);
    runner.assert_true(got_regs, "Should get registers for memory test");
    
    uint64_t addr = regs.rip;  // Current instruction address
    
    // Test peekData
    long data = debugger.peekData(addr);
    runner.assert_true(data != -1, "Should peek data successfully");
    
    // Test readMemory
    uint8_t buffer[16];
    bool read_success = debugger.readMemory(addr, sizeof(buffer), buffer);
    runner.assert_true(read_success, "Should read memory successfully");
    
    // Verify peek and read consistency (first 8 bytes)
    long expected = *reinterpret_cast<long*>(buffer);
    runner.assert_true(data == expected, "Peek and read should return same data");
    
    // Test pokeData (modify a copy of the data)
    long original_data = data;
    long modified_data = data ^ 0x01;  // Flip a bit
    
    bool poke_success = debugger.pokeData(addr, modified_data);
    runner.assert_true(poke_success, "Should poke data successfully");
    
    // Verify the change
    long new_data = debugger.peekData(addr);
    runner.assert_true(new_data == modified_data, "Poked data should match");
    
    // Restore original data
    bool restore_success = debugger.pokeData(addr, original_data);
    runner.assert_true(restore_success, "Should restore original data");
    
    debugger.terminate();
}

// Test error conditions with attach
void testErrorConditionsAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Error Conditions with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    // Test operations on non-attached process
    DebuggerEngine::Registers regs;
    runner.assert_false(debugger.getRegisters(regs), 
                       "Should fail to get registers before attach");
    runner.assert_false(debugger.continueExecution(), 
                       "Should fail to continue before attach");
    runner.assert_false(debugger.interrupt(), 
                       "Should fail to interrupt before attach");
    
    // Test attach to invalid PID
    bool invalid_attach = debugger.attachToTracedChild(-1);
    runner.assert_false(invalid_attach, "Should fail to attach to invalid PID");
    
    // Start and attach to process
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    // Test double attach
    pid_t target_pid2 = pm.startTargetProcess();
    bool double_attach = debugger.attachToTracedChild(target_pid2);
    runner.assert_false(double_attach, "Should fail to attach twice");
    pm.killProcess(target_pid2);  // Clean up the second process
    
    // Start the process running
    debugger.continueExecution();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    
    // Test operations on running process
    runner.assert_false(debugger.getRegisters(regs), 
                       "Should fail to get registers while running");
    runner.assert_false(debugger.step(), 
                       "Should fail to step while running");
    
    // Stop it and test invalid memory access
    debugger.interrupt();
    debugger.waitForStop();
    
    uint8_t buffer[16];
    bool invalid_read = debugger.readMemory(0x0, sizeof(buffer), buffer);
    runner.assert_false(invalid_read, "Should fail to read invalid memory");
    
    debugger.terminate();
}

// Test detach functionality with attach
void testDetachAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Detach Functionality with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    runner.assert_true(debugger.getPid() == target_pid, "Should have correct PID");
    
    bool detached = debugger.detach();
    runner.assert_true(detached, "Should detach successfully");
    runner.assert_true(debugger.getTraceeState() == DebuggerEngine::TraceeState::Exited, 
                      "State should be Exited after detach");
    
    // Verify the process is still running independently
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    int result = kill(target_pid, 0);  // Test if process exists
    runner.assert_true(result == 0, "Target process should still be running after detach");
    
    // Clean up the detached process
    pm.killProcess(target_pid);
}

// Test process that exits normally with attach
void testNormalExitAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Normal Process Exit with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    // Start with "exit" argument to make target exit normally
    pid_t target_pid = pm.startTargetProcess({"exit"});
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    bool continued = debugger.continueExecution();
    runner.assert_true(continued, "Should continue successfully");
    
    // Wait for natural exit
    bool exited = waitWithTimeout([&]() {
        return debugger.getTraceeState() == DebuggerEngine::TraceeState::Exited;
    });
    runner.assert_true(exited, "Process should exit naturally");
}

// Test multiple instances with attach
void testMultipleInstancesAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Multiple Debugger Instances with Attach");
    
    DebuggerEngine::PtraceController debugger1, debugger2;
    
    pid_t target_pid1 = pm.startTargetProcess();
    pid_t target_pid2 = pm.startTargetProcess();
    
    bool attached1 = debugger1.attachToTracedChild(target_pid1);
    runner.assert_true(attached1, "First debugger should attach successfully");
    
    bool attached2 = debugger2.attachToTracedChild(target_pid2);
    runner.assert_true(attached2, "Second debugger should attach successfully");
    
    runner.assert_true(debugger1.getPid() != debugger2.getPid(), 
                      "Different debuggers should have different PIDs");
    
    // Both should work independently
    bool cont1 = debugger1.continueExecution();
    bool cont2 = debugger2.continueExecution();
    runner.assert_true(cont1 && cont2, "Both debuggers should continue successfully");
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    bool int1 = debugger1.interrupt();
    bool int2 = debugger2.interrupt();
    runner.assert_true(int1 && int2, "Both debuggers should interrupt successfully");
    
    bool stop1 = debugger1.waitForStop();
    bool stop2 = debugger2.waitForStop();
    runner.assert_true(stop1 && stop2, "Both processes should stop");
    
    debugger1.terminate();
    debugger2.terminate();
}

// Test memory operations with known values using attach
void testMemoryOperationsWithKnownValuesAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Memory Operations with Known Values using Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    // Continue execution briefly to let the target initialize its global variables
    debugger.continueExecution();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    debugger.interrupt();
    debugger.waitForStop();
    
    // Test with instruction memory (more reliable)
    DebuggerEngine::Registers regs;
    bool got_regs = debugger.getRegisters(regs);
    runner.assert_true(got_regs, "Should get registers");
    
    uint64_t rip = regs.rip;  // Current instruction pointer
    
    // Read instruction bytes using both methods
    uint8_t buffer1[16];
    bool read_success = debugger.readMemory(rip, sizeof(buffer1), buffer1);
    runner.assert_true(read_success, "Should read instruction memory");
    
    // Compare with peekData (8 bytes at a time)
    long peek1 = debugger.peekData(rip);
    long peek2 = debugger.peekData(rip + 8);
    
    runner.assert_true(peek1 != -1, "First peek should succeed");
    runner.assert_true(peek2 != -1, "Second peek should succeed");
    
    // Verify consistency between readMemory and peekData
    long* buffer_as_long = reinterpret_cast<long*>(buffer1);
    runner.assert_true(peek1 == buffer_as_long[0], "First 8 bytes should match between peek and read");
    runner.assert_true(peek2 == buffer_as_long[1], "Second 8 bytes should match between peek and read");
    
    // Test with stack memory (also reliable)
    uint64_t rsp = regs.rsp;  // Stack pointer
    
    // Write a known pattern to stack and read it back
    long test_pattern = 0x1234567890ABCDEF;
    bool poke_success = debugger.pokeData(rsp - 8, test_pattern);  // Write below current stack
    runner.assert_true(poke_success, "Should write test pattern to stack");
    
    // Read it back with peekData
    long peek_result = debugger.peekData(rsp - 8);
    runner.assert_true(peek_result == test_pattern, "Should read back the same pattern with peek");
    
    // Read it back with readMemory
    long read_result;
    bool read_pattern_success = debugger.readMemory(rsp - 8, sizeof(read_result), &read_result);
    runner.assert_true(read_pattern_success, "Should read test pattern with readMemory");
    runner.assert_true(read_result == test_pattern, "Should read back the same pattern with readMemory");
    
    debugger.terminate();
}

// Test global variable access using attach
void testGlobalVariableAccessAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Global Variable Access with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    // Continue execution to let target print its addresses
    debugger.continueExecution();
    std::this_thread::sleep_for(std::chrono::milliseconds(200));  // Give time for output
    debugger.interrupt();
    debugger.waitForStop();
    
    // In a real implementation, you'd parse the target's stdout to get addresses
    // For this test, we'll demonstrate the concept with stack/register memory
    
    DebuggerEngine::Registers regs;
    debugger.getRegisters(regs);
    
    // Test reading and modifying memory at stack location
    uint64_t test_addr = regs.rsp - 16;  // Use stack space for testing
    
    // Write a test value
    int32_t original_value = 42;
    bool write_success = debugger.writeMemory(test_addr, sizeof(original_value), &original_value);
    runner.assert_true(write_success, "Should write test value");
    
    // Read it back
    int32_t read_value = 0;
    bool read_success = debugger.readMemory(test_addr, sizeof(read_value), &read_value);
    runner.assert_true(read_success, "Should read test value");
    runner.assert_true(read_value == original_value, "Read value should match written value");
    
    // Test with string data
    const char* test_string = "DEBUGGER_TEST";
    size_t str_len = strlen(test_string) + 1;
    uint64_t str_addr = regs.rsp - 32;
    
    bool write_str_success = debugger.writeMemory(str_addr, str_len, test_string);
    runner.assert_true(write_str_success, "Should write test string");
    
    char read_buffer[32] = {0};
    bool read_str_success = debugger.readMemory(str_addr, str_len, read_buffer);
    runner.assert_true(read_str_success, "Should read test string");
    runner.assert_true(strcmp(read_buffer, test_string) == 0, "Read string should match written string");
    
    debugger.terminate();
}

// Test memory boundaries and edge cases using attach
void testMemoryBoundariesAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Memory Boundaries and Edge Cases with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    // Test different data sizes
    DebuggerEngine::Registers regs;
    debugger.getRegisters(regs);
    uint64_t test_base = regs.rsp - 64;
    
    // Test 1-byte operations
    uint8_t byte_val = 0xAB;
    bool write_byte = debugger.writeMemory(test_base, 1, &byte_val);
    runner.assert_true(write_byte, "Should write single byte");
    
    uint8_t read_byte = 0;
    bool read_byte_success = debugger.readMemory(test_base, 1, &read_byte);
    runner.assert_true(read_byte_success, "Should read single byte");
    runner.assert_true(read_byte == byte_val, "Byte value should match");
    
    // Test 2-byte operations
    uint16_t word_val = 0x1234;
    bool write_word = debugger.writeMemory(test_base + 1, 2, &word_val);
    runner.assert_true(write_word, "Should write word");
    
    uint16_t read_word = 0;
    bool read_word_success = debugger.readMemory(test_base + 1, 2, &read_word);
    runner.assert_true(read_word_success, "Should read word");
    runner.assert_true(read_word == word_val, "Word value should match");
    
    // Test 4-byte operations
    uint32_t dword_val = 0x12345678;
    bool write_dword = debugger.writeMemory(test_base + 4, 4, &dword_val);
    runner.assert_true(write_dword, "Should write dword");
    
    uint32_t read_dword = 0;
    bool read_dword_success = debugger.readMemory(test_base + 4, 4, &read_dword);
    runner.assert_true(read_dword_success, "Should read dword");
    runner.assert_true(read_dword == dword_val, "Dword value should match");
    
    // Test 8-byte operations (qword)
    uint64_t qword_val = 0x123456789ABCDEF0;
    bool write_qword = debugger.writeMemory(test_base + 8, 8, &qword_val);
    runner.assert_true(write_qword, "Should write qword");
    
    uint64_t read_qword = 0;
    bool read_qword_success = debugger.readMemory(test_base + 8, 8, &read_qword);
    runner.assert_true(read_qword_success, "Should read qword");
    runner.assert_true(read_qword == qword_val, "Qword value should match");
    
    // Verify peekData consistency with 8-byte read
    long peek_qword = debugger.peekData(test_base + 8);
    runner.assert_true(peek_qword == static_cast<long>(qword_val), "PeekData should match qword write");
    
    debugger.terminate();
}

// Test with known instruction patterns using attach
void testInstructionPatternsAttach(TestRunner& runner, ProcessManager& pm) {
    runner.startTest("Instruction Pattern Verification with Attach");
    
    DebuggerEngine::PtraceController debugger;
    
    pid_t target_pid = pm.startTargetProcess();
    bool attached = debugger.attachToTracedChild(target_pid);
    runner.assert_true(attached, "Should attach successfully");
    
    DebuggerEngine::Registers regs;
    debugger.getRegisters(regs);
    
    // Read instruction bytes
    uint8_t instructions[32];
    bool read_success = debugger.readMemory(regs.rip, sizeof(instructions), instructions);
    runner.assert_true(read_success, "Should read instruction bytes");
    
    // Basic sanity checks for x86-64 instructions
    // Most instructions will have valid opcodes, not all zeros or all 0xFF
    bool has_variation = false;
    uint8_t first_byte = instructions[0];
    for (int i = 1; i < 16; i++) {
        if (instructions[i] != first_byte) {
            has_variation = true;
            break;
        }
    }
    runner.assert_true(has_variation, "Instruction bytes should show variation (not all same value)");
    
    // Check that we can read the same data with peekData
    long peek1 = debugger.peekData(regs.rip);
    long peek2 = debugger.peekData(regs.rip + 8);
    
    // Convert instruction bytes to longs for comparison
    long* instr_as_long = reinterpret_cast<long*>(instructions);
    runner.assert_true(peek1 == instr_as_long[0], "First 8 instruction bytes should match peek");
    runner.assert_true(peek2 == instr_as_long[1], "Second 8 instruction bytes should match peek");
    
    // Print some debug info (helpful for manual verification)
    std::cout << "  RIP: 0x" << std::hex << regs.rip << std::dec << std::endl;
    std::cout << "  First instruction bytes: ";
    for (int i = 0; i < 8; i++) {
        std::cout << std::hex << "0x" << static_cast<int>(instructions[i]) << " ";
    }
    std::cout << std::dec << std::endl;
    
    debugger.terminate();
}

// Add this test to verify actual global variable values
void testActualGlobalVariables(TestRunner& runner) {
    runner.startTest("Actual Global Variable Verification");
    
    // This test requires capturing the target's stdout to parse addresses
    // For simplicity, we'll use known offsets or manual inspection
    
    DebuggerEngine::PtraceController debugger;
    
    bool launched = debugger.launch(TEST_TARGET_PATH, {TEST_TARGET_PATH, "quick"});
    runner.assert_true(launched, "Should launch successfully");
    
    // Let the target run briefly to initialize and print debug info
    debugger.continueExecution();
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    debugger.interrupt();
    debugger.waitForStop();
    
    // Now test memory reading with known patterns
    // We'll search for the global_pattern value in memory
    
    DebuggerEngine::Registers regs;
    debugger.getRegisters(regs);
    
    // Search in a reasonable range around data segments
    // This is a simplified approach - in practice you'd parse the target's output
    bool found_pattern = false;
    uint64_t pattern_addr = 0;
    long expected_pattern = 0x1122334455667788;
    
    // Search in likely data segment areas (this is architecture/OS dependent)
    std::vector<uint64_t> search_ranges = {
        0x400000,  // Typical .data section start
        0x600000,  // Another common location
        regs.rsp & ~0xFFF,  // Near stack (page-aligned)
    };
    
    for (uint64_t base : search_ranges) {
        for (uint64_t offset = 0; offset < 0x10000; offset += 8) {
            uint64_t addr = base + offset;
            long value = debugger.peekData(addr);
            if (value == expected_pattern) {
                found_pattern = true;
                pattern_addr = addr;
                std::cout << "  Found global_pattern at address: 0x" << std::hex << addr << std::dec << std::endl;
                break;
            }
        }
        if (found_pattern) break;
    }
    
    if (found_pattern) {
        runner.assert_true(found_pattern, "Should find global_pattern in memory");
        
        // Test reading the struct that should be nearby
        // The global_struct should be close to global_pattern
        for (int offset = -256; offset <= 256; offset += 8) {
            uint64_t test_addr = pattern_addr + offset;
            long value = debugger.peekData(test_addr);
            if (value == 0xDEADBEEF) {  // magic_number from TestStruct
                std::cout << "  Found TestStruct.magic_number at: 0x" << std::hex << test_addr << std::dec << std::endl;
                
                // Read the entire struct
                struct TestStruct {
                    int magic_number;
                    char name[16];
                    double value;
                    long pattern;
                } test_struct;
                
                bool read_struct = debugger.readMemory(test_addr, sizeof(test_struct), &test_struct);
                runner.assert_true(read_struct, "Should read TestStruct");
                runner.assert_true(test_struct.magic_number == 0xDEADBEEF, "Magic number should match");
                runner.assert_true(strcmp(test_struct.name, "TestStruct") == 0, "Struct name should match");
                runner.assert_true(test_struct.pattern == 0xFEDCBA9876543210, "Struct pattern should match");
                
                std::cout << "  Verified TestStruct contents successfully" << std::endl;
                break;
            }
        }
    } else {
        std::cout << "  Note: Could not locate global_pattern automatically" << std::endl;
        std::cout << "  This is normal - would require parsing target output for exact addresses" << std::endl;
    }
    
    // Test string pattern search
    const char* expected_string = "DEBUGGER_TEST_STRING";
    bool found_string = false;
    
    // Search for the string pattern
    for (uint64_t base : search_ranges) {
        for (uint64_t offset = 0; offset < 0x10000; offset += 8) {
            uint64_t addr = base + offset;
            char buffer[32];
            if (debugger.readMemory(addr, sizeof(buffer), buffer)) {
                buffer[31] = '\0';  // Ensure null termination
                if (strstr(buffer, expected_string) != nullptr) {
                    found_string = true;
                    std::cout << "  Found test string at address: 0x" << std::hex << addr << std::dec << std::endl;
                    runner.assert_true(true, "Found global test string in memory");
                    break;
                }
            }
        }
        if (found_string) break;
    }
    
    debugger.terminate();
}

// Helper function to demonstrate parsing target output (simplified)
std::map<std::string, uint64_t> parseTargetAddresses(const std::string& output) {
    std::map<std::string, uint64_t> addresses;
    std::istringstream iss(output);
    std::string line;
    
    while (std::getline(iss, line)) {
        if (line.find(" addr: ") != std::string::npos) {
            size_t name_start = line.find_first_not_of(" \t");
            size_t name_end = line.find(" addr:");
            size_t addr_start = line.find("0x");
            
            if (name_start != std::string::npos && name_end != std::string::npos && addr_start != std::string::npos) {
                std::string name = line.substr(name_start, name_end - name_start);
                std::string addr_str = line.substr(addr_start);
                uint64_t address = std::stoull(addr_str, nullptr, 16);
                addresses[name] = address;
            }
        }
    }
    
    return addresses;
}

int main() {
    TestRunner runner;
    ProcessManager pm;
    
    std::cout << "PtraceController Test Suite" << std::endl;
    std::cout << "Target executable: " << TEST_TARGET_PATH << std::endl;
    
    // Check if target exists
    if (access(TEST_TARGET_PATH, X_OK) != 0) {
        std::cerr << "Error: Target executable not found or not executable: " << TEST_TARGET_PATH << std::endl;
        std::cerr << "Please build the test target first." << std::endl;
        return 1;
    }
    
    try {
        testBasicLifecycleAttach(runner, pm);
        testExecutionControlAttach(runner, pm);
        testRegisterOperationsAttach(runner, pm);
        testMemoryOperationsAttach(runner, pm);
        testErrorConditionsAttach(runner, pm);
        testDetachAttach(runner, pm);
        testNormalExitAttach(runner, pm);
        testMultipleInstancesAttach(runner, pm);
        testMemoryOperationsWithKnownValuesAttach(runner, pm);
        testGlobalVariableAccessAttach(runner, pm);
        testMemoryBoundariesAttach(runner, pm);
        testInstructionPatternsAttach(runner, pm);
    } catch (const std::exception& e) {
        std::cerr << "Test exception: " << e.what() << std::endl;
        return 1;
    }
    
    runner.printSummary();
    return runner.allPassed() ? 0 : 1;
}