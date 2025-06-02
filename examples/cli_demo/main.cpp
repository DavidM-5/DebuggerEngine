#include <iostream>
#include <chrono>
#include <thread>
#include "../../src/PtraceController.h"

#define TARGET_PATH "./bin/test_target"

using ChildSetupHook = std::function<void()>;
using ParentSetupHook = std::function<void(pid_t child_pid)>;


pid_t createChildProcess(const std::string& program, 
                        const std::vector<std::string>& args, 
                        const std::vector<DebuggerEngine::ProcessHooks>& all_hooks) {
    
    pid_t child_pid = fork();
    
    if (child_pid == -1) {
        perror("fork");
        return -1;
    }
    
    if (child_pid == 0) {
        // CHILD PROCESS
        
        // Execute all child setup hooks
        for (const auto& hooks : all_hooks) {
            if (hooks.child_setup) {
                hooks.child_setup();
            }
        }
        
        // Convert std::vector<std::string> to char* const* for execvp
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(program.c_str()));  // argv[0] is program name
        
        for (const auto& arg : args) {
            argv.push_back(const_cast<char*>(arg.c_str()));
        }
        argv.push_back(nullptr);  // execvp expects null-terminated array
        
        // Replace the child process image with the target program
        execvp(program.c_str(), argv.data());
        
        // execvp only returns on error
        perror("execvp");
        exit(1);
        
    } else {
        // PARENT PROCESS
        
        // Execute all parent setup hooks
        for (const auto& hooks : all_hooks) {
            if (hooks.parent_setup) {
                hooks.parent_setup(child_pid);
            }
        }
        
        return child_pid;
    }
}


int main(int argc, char const *argv[]) {
    DebuggerEngine::PtraceController debugger;

    std::vector<DebuggerEngine::ProcessHooks> all_hooks;
    all_hooks.emplace_back(debugger.getProcessHooks());  // Direct usage

    pid_t child_pid = createChildProcess(TARGET_PATH, {TARGET_PATH}, all_hooks);


    std::cout << "Attaching." << std::endl;
    if (!debugger.attachToProcess(child_pid)) {
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