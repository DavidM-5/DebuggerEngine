// Enhanced test_target.cpp with predictable memory patterns
#include <iostream>
#include <unistd.h>
#include <string>
#include <vector>
#include <signal.h>
#include <cstring>

// Global variables with known, predictable values for testing
volatile int global_counter = 12345;
volatile char global_char_array[32] = "DEBUGGER_TEST_STRING";
volatile double global_double = 3.14159;
volatile long global_pattern = 0x1122334455667788;

// Structure with known layout for testing
struct TestStruct {
    int magic_number = 0xDEADBEEF;
    char name[16] = "TestStruct";
    double value = 2.71828;
    long pattern = 0xFEDCBA9876543210;
} volatile global_struct;

// Function that can be single-stepped through
void simple_loop() {
    for (int i = 0; i < 5; ++i) {
        global_counter++;
        usleep(10000); // 10ms
    }
}

// Function to cause a segmentation fault
void cause_segfault() {
    std::cout << "Target: Attempting to cause segfault...\n";
    volatile int* null_ptr = nullptr;
    *null_ptr = 42;
}

// Function to print memory addresses and values for debugger verification
void print_debug_info() {
    std::cout << "=== DEBUG INFO ===" << std::endl;
    std::cout << "PID: " << getpid() << std::endl;
    
    // Print addresses
    std::cout << "global_counter addr: " << (void*)&global_counter << std::endl;
    std::cout << "global_char_array addr: " << (void*)&global_char_array << std::endl;
    std::cout << "global_double addr: " << (void*)&global_double << std::endl;
    std::cout << "global_pattern addr: " << (void*)&global_pattern << std::endl;
    std::cout << "global_struct addr: " << (void*)&global_struct << std::endl;
    std::cout << "simple_loop addr: " << (void*)&simple_loop << std::endl;
    std::cout << "cause_segfault addr: " << (void*)&cause_segfault << std::endl;
    
    // Print current values
    std::cout << "global_counter value: " << global_counter << std::endl;
    std::cout << "global_char_array value: '" << global_char_array << "'" << std::endl;
    std::cout << "global_double value: " << global_double << std::endl;
    std::cout << "global_pattern value: 0x" << std::hex << global_pattern << std::dec << std::endl;
    std::cout << "global_struct.magic_number: 0x" << std::hex << global_struct.magic_number << std::dec << std::endl;
    std::cout << "global_struct.name: '" << global_struct.name << "'" << std::endl;
    std::cout << "global_struct.value: " << global_struct.value << std::endl;
    std::cout << "global_struct.pattern: 0x" << std::hex << global_struct.pattern << std::dec << std::endl;
    std::cout << "=================" << std::endl;
    std::cout.flush();
}

int main(int argc, char* argv[]) {
    print_debug_info();
    
    // Handle command line arguments
    if (argc > 1) {
        std::string arg = argv[1];
        if (arg == "segfault") {
            cause_segfault();
        } else if (arg == "exit") {
            std::cout << "Target: Exiting normally.\n";
            return 0;
        } else if (arg == "quick") {
            // Run for a short time then exit
            std::cout << "Target: Running quick test mode.\n";
            simple_loop();
            std::cout << "Target: Quick mode finished.\n";
            return 0;
        }
    }
    
    std::cout << "Target: Running main loop. global_counter = " << global_counter << std::endl;
    
    // Main loop
    int loop_count = 0;
    while (true) {
        simple_loop();
        loop_count++;
        
        std::cout << "Target: Loop " << loop_count 
                  << ", global_counter = " << global_counter 
                  << ", global_char_array = '" << global_char_array << "'" << std::endl;
        
        // Print debug info periodically
        if (loop_count % 5 == 0) {
            print_debug_info();
        }
        
        sleep(2);
    }
    
    return 0;
}