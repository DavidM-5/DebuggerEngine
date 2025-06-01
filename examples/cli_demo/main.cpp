#include <iostream>
#include <chrono>
#include <thread>
#include "../../src/PtraceController.h"

#define TARGET_PATH "./bin/test_target"

int main(int argc, char const *argv[]) {
    DebuggerEngine::PtraceController debugger;


    std::cout << "Launching." << std::endl;
    if (!debugger.launch(TARGET_PATH, {TARGET_PATH})) {
        std::cerr << "Failed to launch target process" << std::endl;
        return 1;  // Destructor will run and clean up
    }


    std::this_thread::sleep_for(std::chrono::seconds(3));


    std::cout << "Continuing." << std::endl;
    if (!debugger.continueExecution()) {
        std::cerr << "Failed to continue execution" << std::endl;
        return 1;  // Destructor will run and clean up
    }


    std::this_thread::sleep_for(std::chrono::seconds(3));

    
    std::cout << "Interrupting." << std::endl;
    if (!debugger.interrupt()) {
        std::cerr << "Failed to interrupt process" << std::endl;
        return 1;  // Destructor will run and clean up
    }


    std::this_thread::sleep_for(std::chrono::seconds(3));


    std::cout << "Continuing." << std::endl;
    if (!debugger.continueExecution()) {
        std::cerr << "Failed to continue execution" << std::endl;
        return 1;  // Destructor will run and clean up
    }


    std::this_thread::sleep_for(std::chrono::seconds(3));


    std::cout << "Terminating." << std::endl;
    if (!debugger.terminate()) {
        std::cerr << "Failed to terminate process cleanly" << std::endl;
        return 1;  // Destructor will run and clean up
    }


    std::cout << "Done." << std::endl;
    return 0;
}